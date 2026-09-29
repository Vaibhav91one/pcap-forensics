"""Catalog of every finding code: its detector, user-facing category and a short title (issue #47).

This is the only place categories come from. A detector that emits a new code must add it here;
``tests/test_rules_catalog.py`` fails otherwise.
"""

from __future__ import annotations

from typing import NamedTuple

#: Display order of categories in summaries. "Other" catches codes missing from the catalog.
CATEGORIES: tuple[str, ...] = ("Crypto", "Credentials", "Cleartext", "DNS", "SSH & QUIC", "Voice", "Network", "Other")


class Rule(NamedTuple):
    code: str
    detector: str
    category: str
    title: str


_TLS = "d1.tls_cipher"
_TRANSPORT = "d2.transport_exposure"
_VOICE = "d3.sip_rtp"
_DNS_QUIC_SSH = "d4.dns_quic_ssh"

RULES: dict[str, Rule] = {
    rule.code: rule
    for rule in (
        Rule("TLS_VERSION_DEPRECATED", _TLS, "Crypto", "Deprecated TLS/DTLS version negotiated"),
        Rule("TLS_LEGACY_RECORD_VERSION", _TLS, "Crypto", "Legacy record-layer version field"),
        Rule("TLS_CIPHER_UNKNOWN", _TLS, "Crypto", "Cipher suite missing from the registry"),
        Rule("TLS_CIPHER_WEAK", _TLS, "Crypto", "Weak or prohibited cipher suite negotiated"),
        Rule("TLS_OFFERS_WEAK_CIPHERS", _TLS, "Crypto", "Client offers weak cipher suites"),
        Rule("TLS_NO_FORWARD_SECRECY", _TLS, "Crypto", "No forward secrecy"),
        Rule("TLS_CERT_EXPIRED", _TLS, "Crypto", "Certificate already expired during the capture"),
        Rule("TLS_CERT_EXPIRED_NOW", _TLS, "Crypto", "Certificate has expired since the capture"),
        Rule("TLS_CERT_EXPIRING", _TLS, "Crypto", "Certificate close to expiry"),
        Rule("TLS_CERT_WEAK_KEY", _TLS, "Crypto", "Weak certificate key"),
        Rule("TLS_CERT_WEAK_SIGALG", _TLS, "Crypto", "Weak certificate signature algorithm"),
        Rule("TLS_SELF_SIGNED_CHAIN", _TLS, "Crypto", "Self-signed certificate chain"),
        Rule("TLS_FATAL_ALERT", _TLS, "Crypto", "Fatal TLS alert"),
        Rule("TLS_WARNING_ALERT", _TLS, "Crypto", "TLS warning alert"),
        Rule("TLS_HANDSHAKE_TRUNCATED", _TLS, "Crypto", "Truncated TLS handshake"),
        Rule("TLS_JA3_FLEET", _TLS, "Crypto", "Client JA3 fingerprint fleet"),
        Rule("CLEARTEXT_CREDENTIAL", _TRANSPORT, "Credentials", "Credential sent in cleartext"),
        Rule("HTTP_BASIC_AUTH", _TRANSPORT, "Credentials", "HTTP Basic authentication"),
        Rule("HTTP_CLEARTEXT_AUTH", _TRANSPORT, "Credentials", "HTTP authentication over cleartext"),
        Rule("HTTP_COOKIE_NO_SECURE", _TRANSPORT, "Credentials", "Cookie without the Secure flag"),
        Rule("CLEARTEXT_SERVICE", _TRANSPORT, "Cleartext", "Cleartext service"),
        Rule("SERVICE_ON_ODD_PORT", _TRANSPORT, "Network", "Service on a non-standard port"),
        Rule("SYN_SCAN_SHAPE", _TRANSPORT, "Network", "Unanswered-SYN scan shape"),
        Rule("BEACONING_SHAPE", _TRANSPORT, "Network", "Beaconing (regular callbacks)"),
        Rule("SIP_CLEARTEXT_SIGNALLING", _VOICE, "Voice", "Cleartext SIP signalling"),
        Rule("SDP_NO_CRYPTO_ATTR", _VOICE, "Voice", "SDP offered without SRTP keys"),
        Rule("RTP_MEDIA_UNPROTECTED", _VOICE, "Voice", "Unprotected RTP media"),
        Rule("RTP_VOLUME_ANOMALY", _VOICE, "Voice", "RTP media volume anomaly"),
        Rule("DNS_CLEARTEXT", _DNS_QUIC_SSH, "DNS", "Cleartext DNS"),
        Rule("DNS_TUNNEL_SHAPE", _DNS_QUIC_SSH, "DNS", "DNS tunnelling shape"),
        Rule("DNS_EXTERNAL_RESOLVER", _DNS_QUIC_SSH, "DNS", "External DNS resolver in use"),
        Rule("QUIC_PAYLOAD_OPAQUE", _DNS_QUIC_SSH, "SSH & QUIC", "QUIC payload opaque without a keylog"),
        Rule("SSH_WEAK_KEX", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH key exchange offered"),
        Rule("SSH_WEAK_CIPHER", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH cipher offered"),
        Rule("SSH_WEAK_MAC", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH MAC offered"),
        Rule("SSH_WEAK_HOSTKEY", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH host-key algorithm offered"),
        Rule("SSH_TERRAPIN_EXPOSED", _DNS_QUIC_SSH, "SSH & QUIC", "Terrapin (CVE-2023-48795) exposure"),
    )
}


def category_of(code: str) -> str:
    """User-facing category of a finding code; "Other" for a code missing from the catalog."""
    rule = RULES.get(code)
    return rule.category if rule else "Other"
