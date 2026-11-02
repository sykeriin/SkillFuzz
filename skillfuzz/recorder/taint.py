"""Find honeytoken markers (in any of the encodings in Honeytokens.variants) inside network and file data."""
from __future__ import annotations

import urllib.parse

from ..sandbox.honeytokens import Honeytokens


class TaintScanner:
    def __init__(self, tokens: Honeytokens):
        self.byte_variants = {k.encode(): v for k, v in tokens.variants().items()}
        self.lower_variants = {k.lower().encode(): v for k, v in tokens.variants().items()}

    def scan(self, data: bytes) -> set[str]:
        hits = {cls for v, cls in self.byte_variants.items() if v in data}
        if not hits:
            unq = urllib.parse.unquote_to_bytes(data)
            hits = {cls for v, cls in self.byte_variants.items() if v in unq}
        return hits

    def scan_dns(self, name: str) -> set[str]:
        """DNS is case-insensitive on the wire; compare lower-cased and with dots removed (label splitting)."""
        n = name.lower().encode()
        flat = n.replace(b".", b"")
        return {cls for v, cls in self.lower_variants.items() if v in n or v in flat}
