from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from .models import SslCertResult

LOGGER = logging.getLogger(__name__)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


def _parse_cert_der(der_data: bytes) -> dict[str, Any] | None:
    if not HAVE_CRYPTOGRAPHY:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        info: dict[str, Any] = {}
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        info["commonName"] = cn[0].value if cn else None
        org = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        info["organizationName"] = org[0].value if org else None
        info["issuer_org"] = None
        iorg = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        info["issuer_org"] = iorg[0].value if iorg else None
        icn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        info["issuer_cn"] = icn[0].value if icn else None
        info["not_before"] = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        info["not_after"] = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info["san"] = [str(getattr(x, "value", x)) for x in san_ext.value]
        except x509.ExtensionNotFound:
            info["san"] = []

        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info["key_algorithm"] = "RSA"
            info["key_size"] = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["key_algorithm"] = "ECDSA"
            info["key_size"] = pub.key_size
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            info["key_algorithm"] = "Ed25519"
            info["key_size"] = 256
        elif isinstance(pub, ed448.Ed448PublicKey):
            info["key_algorithm"] = "Ed448"
            info["key_size"] = 448
        elif isinstance(pub, dsa.DSAPublicKey):
            info["key_algorithm"] = "DSA"
            info["key_size"] = pub.key_size
        else:
            info["key_algorithm"] = "unknown"
            info["key_size"] = None

        try:
            tls_feature = cert.extensions.get_extension_for_class(x509.TLSFeature)
            info["ocsp_must_staple"] = any(
                feature == x509.TLSFeatureType.status_request
                for feature in tls_feature.value
            )
        except x509.ExtensionNotFound:
            info["ocsp_must_staple"] = False

        if info["commonName"] and info["issuer_cn"] and info["commonName"] == info["issuer_cn"]:
            info["self_signed"] = True
        elif info["commonName"] and info["issuer_org"] and info.get("organizationName") and info["organizationName"] == info["issuer_org"]:
            info["self_signed"] = True
        else:
            info["self_signed"] = False
        return info
    except Exception as exc:
        LOGGER.debug("Failed to parse DER certificate: %s", exc)
        return None


class SslGrabber:
    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def grab(self, host: str, port: int = 443) -> SslCertResult:
        result = SslCertResult(target=host, port=port)
        try:
            addr = socket.getaddrinfo(host, port)[0][4][0]
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((addr, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    tls.settimeout(self.timeout)
                    result.cipher = tls.cipher()[0] if tls.cipher() else None
                    result.protocol = tls.version()

                    chain = tls.getpeercertchain()
                    if chain:
                        result.cert_chain_length = len(chain)

                    cert = tls.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        result.subject_cn = subject.get("commonName")
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        result.issuer = issuer.get("organizationName", issuer.get("commonName"))
                        result.not_before = cert.get("notBefore")
                        result.not_after = cert.get("notAfter")
                        san_list: list[str] = []
                        for entry in cert.get("subjectAltName", []):
                            san_list.append(f"{entry[0]}:{entry[1]}")
                        result.san = san_list
                        if result.not_after:
                            try:
                                expiry = datetime.strptime(result.not_after, "%b %d %H:%M:%S %Y %Z")
                                result.expired = expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
                            except ValueError:
                                pass
                        if result.subject_cn and issuer.get("commonName") and result.subject_cn == issuer.get("commonName"):
                            result.self_signed = True
                    else:
                        der = tls.getpeercert(binary_form=True)
                        if der:
                            info = _parse_cert_der(der)
                            if info:
                                result.subject_cn = info.get("commonName")
                                result.issuer = info.get("issuer_org") or info.get("issuer_cn")
                                result.not_before = info["not_before"].isoformat() if info.get("not_before") else None
                                result.not_after = info["not_after"].isoformat() if info.get("not_after") else None
                                result.san = info.get("san", [])
                                result.self_signed = info.get("self_signed", False)
                                result.key_algorithm = info.get("key_algorithm")
                                result.key_size = info.get("key_size")
                                result.ocsp_must_staple = info.get("ocsp_must_staple", False)
                                if info.get("not_after"):
                                    result.expired = info["not_after"] < datetime.now(timezone.utc)
        except ssl.SSLCertVerificationError:
            result.warnings.append("SSL certificate verification failed")
        except ssl.SSLError as exc:
            result.warnings.append(f"SSL error: {exc}")
        except socket.timeout:
            result.warnings.append(f"Connection timed out to {host}:{port}")
        except OSError as exc:
            result.warnings.append(f"Connection failed: {exc}")
        return result
