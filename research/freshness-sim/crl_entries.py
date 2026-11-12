"""
Entries of a CRL (revocation date and reason code), for fetch_measured.py and fetch_reasons.py.

The `cryptography` package reads almost every CRL ICP-Brasil publishes. The ones it refuses are read by a small DER
walker that looks only at revokedCertificates (RFC 5280, 5.1): in November 2026 that is the Certisign OM-BR list,
signed with Ed448, and, with versions of the package before 50, the two Serpro lists, for one serial number.

No list is skipped. A list that neither reader decodes stops the run (`decode` exits), because a skipped list is a
hole in every total that follows: the test cut of 7 November 2026 went out without the largest list of the
collection, and nothing failed.
"""
import sys
from datetime import datetime, timezone

from cryptography import x509

REASON_OID = bytes([0x55, 0x1D, 0x15])  # 2.5.29.21, reasonCode
# RFC 5280, 5.3.1, with the names the cryptography package gives them.
REASONS = {0: "unspecified", 1: "key_compromise", 2: "ca_compromise", 3: "affiliation_changed", 4: "superseded",
           5: "cessation_of_operation", 6: "certificate_hold", 8: "remove_from_crl", 9: "privilege_withdrawn",
           10: "aa_compromise"}
SEQUENCE, INTEGER, UTC_TIME, GENERALIZED_TIME = 0x30, 0x02, 0x17, 0x18


def _tlv(b, i):
    """(tag, start, end) of the value of the element at offset i. DER only: definite lengths."""
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4:
            raise ValueError("DER length")
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise ValueError("DER element runs past the end")
    return tag, i, i + n


def _children(b, start, end):
    out = []
    while start < end:
        tag, s, e = _tlv(b, start)
        out.append((tag, s, e))
        start = e
    return out


def _time(tag, v):
    s = v.decode("ascii")
    if tag == UTC_TIME:  # RFC 5280, 4.1.2.5.1: two-digit years from 50 on are 19YY
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    elif tag != GENERALIZED_TIME:
        raise ValueError("not a Time")
    return datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def _reason(b, extensions):
    for _, s, e in _children(b, extensions[1], extensions[2]):
        fields = _children(b, s, e)  # extnID, critical (optional), extnValue
        if b[fields[0][1]:fields[0][2]] == REASON_OID:
            _, vs, _ = _tlv(b, fields[-1][1])  # the ENUMERATED inside the OCTET STRING
            return REASONS[b[vs]]
    return None


def walk(der):
    """[(revocation date in UTC, reason name or None)], reading only what the entries need."""
    try:
        tag, s, e = _tlv(der, 0)  # CertificateList
        if tag != SEQUENCE:
            raise ValueError("not a CertificateList")
        _, s, e = _tlv(der, s)  # TBSCertList
        kids = _children(der, s, e)
        i = 1 if kids[0][0] == INTEGER else 0  # version
        i += 2  # signature, issuer
        _time(kids[i][0], der[kids[i][1]:kids[i][2]])  # thisUpdate
        i += 1
        if i < len(kids) and kids[i][0] in (UTC_TIME, GENERALIZED_TIME):  # nextUpdate
            i += 1
        if i == len(kids) or kids[i][0] != SEQUENCE:  # no revokedCertificates: an empty list
            return []
        out = []
        for _, s, e in _children(der, kids[i][1], kids[i][2]):
            fields = _children(der, s, e)  # userCertificate, revocationDate, crlEntryExtensions (optional)
            when = _time(fields[1][0], der[fields[1][1]:fields[1][2]])
            out.append((when, _reason(der, fields[2]) if len(fields) > 2 else None))
        return out
    except (IndexError, KeyError, UnicodeDecodeError) as e:
        raise ValueError(f"DER walker: {type(e).__name__}: {e}") from e


def _library(der):
    out = []
    for rc in x509.load_der_x509_crl(der):
        # cryptography >= 42 has revocation_date_utc; older versions give a naive UTC datetime.
        when = rc.revocation_date_utc if hasattr(rc, "revocation_date_utc") else rc.revocation_date.replace(tzinfo=timezone.utc)
        try:
            reason = rc.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            reason = None
        out.append((when, reason))
    return out


def decode(der, name):
    """(entries, reader) of one CRL; reader is "cryptography" or "der". Exits when neither reader decodes it."""
    try:
        return _library(der), "cryptography"
    except ValueError as e:
        print(f"warning: {name}: cryptography refuses it ({str(e)[:120]}); reading the entries with the DER walker", file=sys.stderr)
    try:
        return walk(der), "der"
    except ValueError as e:
        raise SystemExit(f"error: {name}: no reader decodes this CRL ({e}). The run stops: a skipped list would be missing from every total.")
