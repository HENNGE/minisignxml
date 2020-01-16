from typing import Tuple

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate
from lxml.builder import ElementMaker

from minisignxml.config import SigningConfig, VerifyConfig
from minisignxml.errors import UnsupportedAlgorithm, VerificationFailed
from minisignxml.internal import utils
from minisignxml.sign import sign
from minisignxml.verify import extract_verified_element


@pytest.fixture
def cert_and_signed() -> Tuple[Certificate, bytes]:
    return (
        load_pem_x509_certificate(
            b"""-----BEGIN CERTIFICATE-----
MIICqjCCAZKgAwIBAgIUVm184XOVf+ZSmOo+MjOT3MIzdSIwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMDAxMTUwNzA4MDhaFw0yMDAxMTYwNzA4
MDhaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC8IAf7PQxlUTeDZodyCdaTY/XtCNBLI5FNGKgVbjePSDDlsn4nBAtaPemG
LNof0lPr4sRjdC5rfwQVtDU21GJMam106RvJcg4eYns51Y2CshDpu6M9Il96Qrp+
9djcdbH0MHPsenR+ChTmKa6XYfRkPCO8WIp08Tl39kP0LJNHKcT9OAc6QlS3igcI
sL2dkiz6Xq7dVgZ27aViz1pWqdxuqfbSOKQSPqcQRGE8spt9KU+r5UFH4z4ZXGum
l/YwscEVKgpzNYdlqE8OpKurm3+pNDuxpbTK+P9Wz0Gq1z5QNP0epaM3bVN0Ft6S
H+y+Pyo5ueX7raGB8HXwqgqI6xOBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFCb
gyUX+Lj2gpx0VqXiYZ8ZCGq644EENsCDHV1fnSq/KuLDuajao6ppEubl5XDs0fba
1jy3aJ30H0vuVJ1eLnpOrh/xpAUtpwr9T98kLilRWEGgAKQTl7dilKkYJ1sBA1OU
v6ERRt+I7NnMXQvvz2VfevulVHQnO1Reo/QCfMrVdVGTfrYkKRzAnxH/g259+Rzp
SB9HhQm6oxf8Z4zAPbAJu2mbxI+wcT40Mbw9BhJR/mb1eGMUtetzp7G1btYUtlH4
Yix0bP72mabQDIRoQjs8bd2/5nkXLPsCB5nUXp0dbIhYk2Qb0iNgzYdDleLS3pIc
EWcj4VxjuYBtQyxhyko=
-----END CERTIFICATE-----""",
            default_backend(),
        ),
        (
            b'<test:root xmlns:test="urn:test">'
            b'<test:signed ID="test">'
            b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            b"<ds:SignedInfo>"
            b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
            b'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>'
            b'<ds:Reference URI="#test">'
            b"<ds:Transforms>"
            b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
            b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
            b"</ds:Transforms>"
            b'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'
            b"<ds:DigestValue>KeOO+93WmuoCL8Ci/llQH18tFfzI81ihpZCiJv0q8EI=</ds:DigestValue>"
            b"</ds:Reference>"
            b"</ds:SignedInfo>"
            b"<ds:SignatureValue>pvAdYfF2NtS3Dm8/4zP1vcxs4G6IpApn0Nl0Wg930fJm7uBC7M4E7RdwiMav9UkYVK8cNrNhUnpsWEwX5anE8JOZLnW9JZ8W4a/i8ZFD7KA8PKu6q9I7HxT7eOdjgVUvZkL6j8Jz0Mf97GPc1mpU1Dyvn4qvnXS7iy6g4tuAYeArKYKJHpXqzE3YEoXnnWOwxf44Tw92YVAPO0fvVJUKY2Nt1Om/QX6oZbpwooJN3iBPgu0Zq805d4rT8J01571flyr0+HWPYDN8Q7iPuZC+zPwzyzMFdOyjbS30qRrtvUf/0gDap+s3Kl0U0AiywSrdhzyyc/5cOrOhbEwDu+8+Uw==</ds:SignatureValue>"
            b"<ds:KeyInfo>"
            b"<ds:X509Data>MIICqjCCAZKgAwIBAgIUVm184XOVf+ZSmOo+MjOT3MIzdSIwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMDAxMTUwNzA4MDhaFw0yMDAxMTYwNzA4MDhaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8IAf7PQxlUTeDZodyCdaTY/XtCNBLI5FNGKgVbjePSDDlsn4nBAtaPemGLNof0lPr4sRjdC5rfwQVtDU21GJMam106RvJcg4eYns51Y2CshDpu6M9Il96Qrp+9djcdbH0MHPsenR+ChTmKa6XYfRkPCO8WIp08Tl39kP0LJNHKcT9OAc6QlS3igcIsL2dkiz6Xq7dVgZ27aViz1pWqdxuqfbSOKQSPqcQRGE8spt9KU+r5UFH4z4ZXGuml/YwscEVKgpzNYdlqE8OpKurm3+pNDuxpbTK+P9Wz0Gq1z5QNP0epaM3bVN0Ft6SH+y+Pyo5ueX7raGB8HXwqgqI6xOBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFCbgyUX+Lj2gpx0VqXiYZ8ZCGq644EENsCDHV1fnSq/KuLDuajao6ppEubl5XDs0fba1jy3aJ30H0vuVJ1eLnpOrh/xpAUtpwr9T98kLilRWEGgAKQTl7dilKkYJ1sBA1OUv6ERRt+I7NnMXQvvz2VfevulVHQnO1Reo/QCfMrVdVGTfrYkKRzAnxH/g259+RzpSB9HhQm6oxf8Z4zAPbAJu2mbxI+wcT40Mbw9BhJR/mb1eGMUtetzp7G1btYUtlH4Yix0bP72mabQDIRoQjs8bd2/5nkXLPsCB5nUXp0dbIhYk2Qb0iNgzYdDleLS3pIcEWcj4VxjuYBtQyxhyko=</ds:X509Data>"
            b"</ds:KeyInfo>"
            b"</ds:Signature>"
            b"<test:content>Value</test:content>"
            b"</test:signed>"
            b"</test:root>"
        ),
    )


def test_verify(xmlsec1, tmp_path, cert_and_signed):
    cert, xml = cert_and_signed

    signed = tmp_path / "signed.xml"
    cert_pem = tmp_path / "cert.pem"
    with signed.open("wb") as fobj:
        fobj.write(xml)
    with cert_pem.open("wb") as fobj:
        fobj.write(cert.public_bytes(encoding=Encoding.PEM))

    xmlsec1(
        "verify",
        "--pubkey-cert-pem",
        str(cert_pem),
        "--id-attr:ID",
        "signed",
        str(signed),
    )

    verified_element = extract_verified_element(xml=xml, certificate=cert)
    assert verified_element is not None
    assert verified_element.tag == "{urn:test}signed"
    assert verified_element.attrib["ID"] == "test"


def test_verify_fail(cert_and_signed):
    cert, xml = cert_and_signed
    broken = xml.replace(
        b"<test:content>Value</test:content>",
        b"<test:content>Changed Value</test:content>",
    )
    with pytest.raises(VerificationFailed):
        extract_verified_element(xml=broken, certificate=cert)


def test_verify_config(key_and_cert):
    ns = ElementMaker(namespace="urn:test", nsmap={"test": "urn:test"})
    element_to_sign = ns.signed(ns.content("Value"), ID="test")
    ns.root(element_to_sign)
    config = SigningConfig(signature_method=hashes.SHA1(), digest_method=hashes.SHA1())
    signed_data = sign(
        element=element_to_sign,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
        config=config,
    )
    with pytest.raises(UnsupportedAlgorithm):
        extract_verified_element(
            xml=signed_data,
            certificate=key_and_cert.certificate,
            config=VerifyConfig(
                allowed_signature_method={hashes.SHA256},
                allowed_digest_method={hashes.SHA256},
            ),
        )
