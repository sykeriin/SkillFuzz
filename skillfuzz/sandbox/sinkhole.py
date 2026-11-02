"""In-sandbox network sinkhole. Runs inside the netns, so nothing here can reach the real network.

* DNS (UDP/53): every A query resolves to a distinct 127.10.x.y address; the mapping is logged so a later
  connect() can be attributed to a hostname. AAAA gets an empty answer.
* HTTP (80, 8080) and HTTPS (443, 8443): requests are logged with full bodies. HTTPS is terminated with a
  throwaway CA (clients are pointed at it through SSL_CERT_FILE & friends) so exfiltration over TLS is readable.
  If a client refuses our certificate we still log the SNI and the fact that a handshake was attempted.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

MAX_BODY = 1_000_000


def cache_dir() -> Path:
    d = Path(os.environ.get("SKF_CACHE") or Path.home() / ".cache" / "skillfuzz")
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_ca() -> tuple[Path, Path]:
    d = cache_dir() / "ca2"
    d.mkdir(exist_ok=True)
    crt, key = d / "ca.pem", d / "ca.key"
    if not crt.exists():
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(key), "-out", str(crt), "-days", "3650", "-subj", "/CN=SkillFuzz Sinkhole CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash"],
            check=True, capture_output=True)
    return crt, key


_HOST_OK = re.compile(r"^[a-z0-9._-]{1,200}$")
_leaf_lock = threading.Lock()


def leaf_cert(host: str) -> Path | None:
    """PEM (cert+key) for `host`, signed by our CA. Cached across runs."""
    host = host.lower()
    if not _HOST_OK.match(host):
        return None
    ca_crt, ca_key = ensure_ca()
    d = cache_dir() / "leaf2"
    d.mkdir(exist_ok=True)
    out = d / f"{host}.pem"
    if out.exists():
        return out
    with _leaf_lock:
        if out.exists():
            return out
        key, csr, crt, ext = (d / f"{host}.{os.getpid()}.{x}.tmp" for x in ("key", "csr", "crt", "ext"))
        # Python >= 3.13 verifies in X509_STRICT mode: it needs AKI/SKI, critical basicConstraints and key usages
        ext.write_text(f"subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        try:
            subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={host}"],
                           check=True, capture_output=True)
            subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
                            "-CAcreateserial", "-out", str(crt), "-days", "365", "-extfile", str(ext)],
                           check=True, capture_output=True)
            tmp = d / f"{host}.{os.getpid()}.pem.tmp"
            tmp.write_bytes(crt.read_bytes() + key.read_bytes())
            tmp.replace(out)
        finally:
            for f in (key, csr, crt, ext):
                f.unlink(missing_ok=True)
    return out


def parse_sni(data: bytes) -> str | None:
    """Extract the server_name from a TLS ClientHello, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32                      # record hdr, handshake hdr, version, random
        pos += 1 + data[pos]                       # session id
        pos += 2 + struct.unpack(">H", data[pos:pos + 2])[0]   # cipher suites
        pos += 1 + data[pos]                       # compression
        ext_end = pos + 2 + struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", data[pos:pos + 4])
            pos += 4
            if etype == 0:                         # server_name
                nlen = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                return data[pos + 5:pos + 5 + nlen].decode("ascii", "replace")
            pos += elen
    except Exception:
        return None
    return None


def build_dns_response(query: bytes, ip: str) -> tuple[bytes, str, int]:
    tid = query[:2]
    pos, labels = 12, []
    while query[pos] != 0:
        ln = query[pos]
        labels.append(query[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    qname = ".".join(labels)
    qtype = struct.unpack(">H", query[pos + 1:pos + 3])[0]
    question = query[12:pos + 5]
    if qtype == 1:
        hdr = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        return hdr + question + ans, qname, qtype
    hdr = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 0, 0, 0)
    return hdr + question, qname, qtype


class Sinkhole:
    def __init__(self, log_path: str | Path, tls: bool = True):
        self.log_path = Path(log_path)
        self.tls = tls
        self._lock = threading.Lock()
        self._names: dict[str, str] = {}     # name -> ip
        self._ips: dict[str, str] = {}       # ip -> name
        self._stop = threading.Event()
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._default_ctx: ssl.SSLContext | None = None
        self.log_path.write_text("")

    # ---- logging -----------------------------------------------------------------
    def log(self, **rec) -> None:
        rec["t"] = time.time()
        with self._lock, self.log_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    # ---- DNS ---------------------------------------------------------------------
    def _ip_for(self, name: str) -> str:
        with self._lock:
            ip = self._names.get(name)
            if ip is None:
                n = len(self._names) + 1
                ip = f"127.10.{n >> 8 & 255}.{n & 255}"
                self._names[name] = ip
                self._ips[ip] = name
        return ip

    def _dns_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                return
            try:
                name = ""
                # peek name first so we can allocate an ip
                pos, labels = 12, []
                while data[pos] != 0:
                    labels.append(data[pos + 1:pos + 1 + data[pos]].decode("ascii", "replace"))
                    pos += 1 + data[pos]
                name = ".".join(labels).lower()
                resp, qname, qtype = build_dns_response(data, self._ip_for(name))
                self.log(type="dns", name=qname.lower(), qtype=qtype, ip=self._names.get(name))
                sock.sendto(resp, addr)
            except Exception as e:  # malformed query
                self.log(type="error", where="dns", err=repr(e))

    # ---- HTTP / TLS --------------------------------------------------------------
    def _ctx_for(self, host: str | None) -> ssl.SSLContext:
        key = host or ""
        if key not in self._ctx_cache:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            pem = leaf_cert(host) if host else None
            if pem is None:
                pem = leaf_cert("localhost")
            ctx.load_cert_chain(str(pem))
            self._ctx_cache[key] = ctx
        return self._ctx_cache[key]

    def _read_http(self, conn: socket.socket) -> tuple[bytes, dict, bytes, bytes]:
        conn.settimeout(3)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
        clen = int(headers.get("content-length", "0") or 0)
        body = rest
        if "chunked" in headers.get("transfer-encoding", "").lower():
            while not body.endswith(b"0\r\n\r\n") and len(body) < MAX_BODY:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                body += chunk
        else:
            while len(body) < min(clen, MAX_BODY):
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                body += chunk
        return lines[0] if lines else b"", headers, body, buf

    def _serve_http(self, conn: socket.socket, scheme: str, dest_ip: str, sni: str | None) -> None:
        try:
            reqline, headers, body, raw = self._read_http(conn)
            parts = reqline.decode("latin1").split(" ")
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("?", "?")
            host = (headers.get("host") or sni or self._ips.get(dest_ip) or dest_ip).split(":")[0].lower()
            self.log(type="http", scheme=scheme, host=host, method=method, path=path,
                     headers={k: v for k, v in headers.items() if k in ("user-agent", "content-type", "authorization", "cookie", "x-api-key")},
                     body_b64=base64.b64encode(body[:MAX_BODY]).decode(), raw_len=len(raw))
            payload = b"# sinkhole\nok\n"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                         + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        except Exception as e:
            self.log(type="error", where="http", err=repr(e))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, conn: socket.socket, port: int) -> None:
        dest_ip = conn.getsockname()[0]
        try:
            conn.settimeout(3)
            first = conn.recv(4096, socket.MSG_PEEK)
        except OSError:
            conn.close()
            return
        if first[:1] == b"\x16":                       # TLS ClientHello
            sni = parse_sni(first)
            host = (sni or self._ips.get(dest_ip) or dest_ip).lower()
            if not self.tls:
                self.log(type="tls_attempt", host=host, sni=sni, outcome="not_terminated")
                conn.close()
                return
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(str(leaf_cert("localhost")))
                ctx.sni_callback = lambda s, name, _c: setattr(s, "context", self._ctx_for(name)) or None
                tls_conn = ctx.wrap_socket(conn, server_side=True)
            except Exception as e:
                self.log(type="tls_attempt", host=host, sni=sni, outcome="handshake_failed", err=repr(e)[:120])
                try:
                    conn.close()
                except OSError:
                    pass
                return
            self._serve_http(tls_conn, "https", dest_ip, sni)
        else:
            self._serve_http(conn, "http", dest_ip, None)

    def _tcp_loop(self, srv: socket.socket, port: int) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            t = threading.Thread(target=self._handle, args=(conn, port), daemon=True)
            t.start()

    # ---- lifecycle ---------------------------------------------------------------
    def start(self) -> None:
        d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        d.bind(("0.0.0.0", 53))
        self._socks.append(d)
        self._threads.append(threading.Thread(target=self._dns_loop, args=(d,), daemon=True))
        for port in (80, 8080, 443, 8443):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(64)
            self._socks.append(s)
            self._threads.append(threading.Thread(target=self._tcp_loop, args=(s, port), daemon=True))
        for t in self._threads:
            t.start()

    def ip_map(self) -> dict[str, str]:
        with self._lock:
            return dict(self._ips)

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self.log(type="ipmap", map=self.ip_map())
