"""Turn operator-supplied key material into tshark decryption ``-o`` args (issue #115).

Authorized white-box use only: the operator supplies a TLS private key / keylog / PSK that they extracted
from a device's firmware (or logged from a client they control), and pcap-doctor hands it to tshark to
decrypt the operator's **own** capture so the inner traffic can be triaged.

Key material is passed straight to tshark and **never** written to a report artifact (AGENTS.md secrets
rule); only the resulting `-o` argument strings live here. An RSA private key decrypts a session only when
it used RSA key exchange (no ECDHE) and matches the *server* certificate; forward-secret sessions are not
decryptable with a static key, which is the point.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

#: Dissector applied to decrypted TLS application data (so decrypted HTTP is parsed as HTTP).
TLS_APP_PROTO = "http"


@dataclass(frozen=True)
class KeyMaterial:
    """Everything the operator supplied to decrypt their capture."""

    tls_keys: tuple[Path, ...] = ()
    tls_key_password: str = ""
    keylog: Path | None = None
    psk: str = ""

    def is_empty(self) -> bool:
        return not (self.tls_keys or self.keylog or self.psk)

    def tshark_args(self) -> list[str]:
        """The `-o` decryption args for tshark, in a stable order (cache-key friendly).

        RSA keys use the modern ``uat:ssl_keys`` form with a wildcard ip/port (``"",""``) so any server
        matches; the obsolete ``tls.keys_list`` preference is never emitted (it hard-fails on tshark 4.x).
        """
        args: list[str] = []
        for key in self.tls_keys:
            row = f'"","","{TLS_APP_PROTO}","{key}","{self.tls_key_password}"'
            args += ["-o", f"uat:ssl_keys:{row}"]
        if self.keylog is not None:
            args += ["-o", f"tls.keylog_file:{self.keylog}"]
        if self.psk:
            args += ["-o", f"tls.psk:{self.psk}", "-o", f"dtls.psk:{self.psk}"]
        return args


def collect(
    tls_key: Iterable[Path] | None = None,
    *,
    tls_key_password: str = "",
    keys_from: Path | None = None,
    keylog: Path | None = None,
    psk: str = "",
) -> KeyMaterial:
    """Build a :class:`KeyMaterial` from CLI inputs, expanding ``keys_from`` into every PEM private key."""
    keys: list[Path] = [Path(k) for k in (tls_key or ())]
    if keys_from is not None:
        keys += private_keys_under(Path(keys_from))
    return KeyMaterial(tuple(keys), tls_key_password, Path(keylog) if keylog else None, psk)


def private_keys_under(root: Path) -> list[Path]:
    """Every PEM file under ``root`` that contains a private key (an extracted firmware tree is the input)."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".pem", ".key"):
            continue
        try:
            if "PRIVATE KEY" in path.read_text(encoding="latin-1", errors="ignore")[:4096]:
                found.append(path)
        except OSError:
            continue
    return found


def firmware_key_spkis(
    firmware_dirs: Iterable[Path], extra_keys: Iterable[Path] = ()
) -> dict[str, str]:
    """Map every firmware private key to its public SPKI fingerprint: ``{spki: display_path}``.

    The fingerprint is the same one a certificate carries, so a match means the private key that
    protects a session on the wire ships in the firmware. Paths are relative to their tree (or a
    bare name for an explicit key); the private bytes never leave openssl.
    """
    from .certificates import spki_of_private_key

    out: dict[str, str] = {}
    for root in firmware_dirs:
        root = Path(root)
        for key in private_keys_under(root):
            fp = spki_of_private_key(str(key))
            if fp:
                out.setdefault(fp, str(key.relative_to(root)))
    for key in extra_keys:
        fp = spki_of_private_key(str(key))
        if fp:
            out.setdefault(fp, Path(key).name)
    return out
