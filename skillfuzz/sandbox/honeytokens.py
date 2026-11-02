"""Honeytokens: fake credentials carrying a run-unique marker so any leak is attributable.

Every value is fake. Nothing here is, or resembles, a working credential beyond its shape.
"""
from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

# secret class -> (path relative to $HOME, short code embedded in the marker)
SECRET_FILES: dict[str, tuple[str, str]] = {
    "aws": (".aws/credentials", "AWS"),
    "ssh": (".ssh/id_ed25519", "SSH"),
    "npm": (".npmrc", "NPM"),
    "gh": (".config/gh/hosts.yml", "GHT"),
    "wallet": (".config/solana/id.json", "WAL"),
    "browser_cookies": (".config/chromium/Default/Cookies", "CKI"),
    "dotenv": ("project/.env", "ENV"),
    "docker": (".docker/config.json", "DKR"),
}
# Extra files that belong to a class (reading them also counts as touching it).
EXTRA_SECRET_PATHS: dict[str, str] = {
    ".aws/config": "aws",
    ".ssh/id_ed25519.pub": "ssh",
}


@dataclass
class Honeytokens:
    run_id: str
    markers: dict[str, str]   # class -> marker

    @classmethod
    def new(cls, run_id: str | None = None) -> "Honeytokens":
        rid = (run_id or secrets.token_hex(4)).upper()[:8]
        # class code FIRST: trimmed base64 variants only cover the stable middle of the marker, so the part that
        # distinguishes secret classes must sit at the front or every class would share the same variant.
        return cls(rid, {c: f"SKF{code}{rid}" for c, (_, code) in SECRET_FILES.items()})

    def class_of_marker(self, marker: str) -> str | None:
        for c, m in self.markers.items():
            if m == marker:
                return c
        return None

    def variants(self) -> dict[str, str]:
        """Every searchable encoding of every marker -> secret class. Used by the taint detector."""
        out: dict[str, str] = {}
        for cls, m in self.markers.items():
            raw = m.encode()
            forms = {m, m.lower(), m[::-1], raw.hex(), raw.hex().upper()}
            forms.add(", ".join(str(b) for b in raw))
            forms.add(",".join(str(b) for b in raw))
            # base32/base64 encode groups of bytes, so the characters at the edges of an encoded marker depend on
            # whatever bytes surround it. For every possible alignment keep only the characters fully determined
            # by the marker's own bytes (a marker embedded in a longer string still matches).
            for encode, bits, aligns in ((base64.b32encode, 5, 5), (base64.b64encode, 6, 3), (base64.urlsafe_b64encode, 6, 3)):
                for pad in range(aligns):
                    enc = encode(b"x" * pad + raw).decode()
                    lo = -(-8 * pad // bits)                       # ceil
                    hi = 8 * (pad + len(raw)) // bits              # floor
                    forms.add(enc[lo:hi])
            for f in forms:
                if len(f) >= 8:
                    out[f] = cls
        return out

    def files(self) -> dict[str, bytes]:
        """relative path -> content."""
        m = self.markers
        fake_pem_body = base64.b64encode((m["ssh"] * 8).encode()).decode()
        wallet = json.dumps([ord(ch) for ch in (m["wallet"] * 4)])
        return {
            ".aws/credentials": (
                f"[default]\naws_access_key_id = AKIA{m['aws']}XX\n"
                f"aws_secret_access_key = {m['aws']}/{m['aws'].lower()}fakefakefake\n"
            ).encode(),
            ".aws/config": b"[default]\nregion = us-east-1\noutput = json\n",
            ".ssh/id_ed25519": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU{fake_pem_body}\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ).encode(),
            ".ssh/id_ed25519.pub": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5{m['ssh']} dev@laptop\n".encode(),
            ".ssh/known_hosts": b"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
            ".npmrc": f"//registry.npmjs.org/:_authToken=npm_{m['npm']}\n".encode(),
            ".config/gh/hosts.yml": (
                f"github.com:\n  user: dev\n  oauth_token: gho_{m['gh']}\n  git_protocol: ssh\n"
            ).encode(),
            ".config/solana/id.json": wallet.encode(),
            ".docker/config.json": json.dumps(
                {"auths": {"https://index.docker.io/v1/": {"auth": base64.b64encode(f"dev:{m['docker']}".encode()).decode()}}}
            ).encode(),
            "project/.env": (
                f"DATABASE_URL=postgres://app:{m['dotenv']}@db.internal:5432/prod\n"
                f"STRIPE_SECRET_KEY=sk_live_{m['dotenv']}\nDEBUG=false\n"
            ).encode(),
        }
