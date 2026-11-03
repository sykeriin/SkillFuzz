"""DSSE (Dead Simple Signing Envelope) with ed25519. Spec: https://github.com/secure-systems-lab/dsse"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

PAYLOAD_TYPE = "application/vnd.in-toto+json"


class AttestationError(Exception):
    """Signature, key or envelope problem (as opposed to a behavioural verdict)."""


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:   # pragma: no cover
        raise AttestationError("pip install 'skillfuzz[attest]' (needs the cryptography package)") from e
    return serialization, ed25519, InvalidSignature


def pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-authentication encoding: signing this, not the raw payload, binds the payload type too."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def keyid(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def keygen(out_dir: str | Path, name: str = "skillfuzz") -> tuple[Path, Path]:
    ser, ed, _ = _crypto()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sk = ed.Ed25519PrivateKey.generate()
    priv, pub = out / f"{name}.key", out / f"{name}.pub"
    priv.write_bytes(sk.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(sk.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def _pub_raw(pub) -> bytes:
    ser, _, _ = _crypto()
    return pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def load_private(path: str | Path):
    ser, ed, _ = _crypto()
    try:
        return ser.load_pem_private_key(Path(path).read_bytes(), password=None)
    except Exception as e:
        raise AttestationError(f"cannot read private key {path}: {e}") from e


def load_public(path: str | Path):
    ser, ed, _ = _crypto()
    try:
        return ser.load_pem_public_key(Path(path).read_bytes())
    except Exception as e:
        raise AttestationError(f"cannot read public key {path}: {e}") from e


def sign(statement: dict, private_key_path: str | Path) -> dict:
    sk = load_private(private_key_path)
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    sig = sk.sign(pae(PAYLOAD_TYPE, payload))
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": keyid(_pub_raw(sk.public_key())), "sig": base64.b64encode(sig).decode()}]}


def verify(envelope: dict, public_key_path: str | Path) -> dict:
    """Return the statement if some signature verifies under the key; raise AttestationError otherwise."""
    _, _, InvalidSignature = _crypto()
    pub = load_public(public_key_path)
    try:
        ptype, payload = envelope["payloadType"], base64.b64decode(envelope["payload"], validate=True)
        sigs = envelope["signatures"]
    except Exception as e:
        raise AttestationError(f"malformed envelope: {e!r}") from e
    if ptype != PAYLOAD_TYPE:
        raise AttestationError(f"unexpected payloadType {ptype!r}")
    kid = keyid(_pub_raw(pub))
    for s in sigs:
        if s.get("keyid") not in (None, kid):
            continue
        try:
            pub.verify(base64.b64decode(s["sig"]), pae(ptype, payload))
            return json.loads(payload)
        except (InvalidSignature, ValueError, KeyError):
            continue
    raise AttestationError("no valid signature for the supplied public key")
