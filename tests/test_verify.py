import base64
import binascii
import itertools
import textwrap
from dataclasses import dataclass
from typing import Tuple

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate
from lxml.builder import E, ElementMaker

from minisignxml.config import SigningConfig, VerifyConfig
from minisignxml.errors import (
    CertificateMismatch,
    MultipleElementsFound,
    UnsupportedAlgorithm,
    VerificationFailed,
)
from minisignxml.internal import utils
from minisignxml.sign import sign
from minisignxml.verify import (
    extract_verified_element,
    extract_verified_element_and_certificate,
)

_private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDW5mB4IVP4ASCr
PKW5vQLAeqDRnpqepjvyqs9rByTNENBzvUUni1jHGAmmmT0QweFYaIW7n2CPynN4
PJRfmdI2Qkj8w6im0NYKGUYoyKy9XC8WMBqKEFBsFt/ByfJYtZncjPYpvBR3jQbZ
ft2FeqNQmUv6GXQA5ul/IifmYnWuDguzlzJklfejOD3YwadMxt7TnMPGxtBpA7IA
icheLTFu25GL+KQmOJ5/aaGRgS821SwKAAGAXBvUTAa6swREhaxx8eo0qg1B/bJa
4BnuMj5y2nxAe1CbiQcOJg09NQcRQFtjBIlr3B6kCLDsDfSJffL1sIiHo8tgAtFa
DwupJ4wrAgMBAAECggEAActx+3OPVSt0iQIJcvy+jjoyTXRy1/L+OKUn5adAD6K3
/U0bNT6pHg5smb0Gh62t5JrqoGnyxeGXKVcqxA2CbomhtUvfuX6SWLAgdxQVQTs9
pn0NPRnDP9NfjJqA1NXT5Seq7J/kVwrnngEXJLHotW6Fm7WopmJWXFhNHvH/B8cc
JXWMvD13tDuZS9hdr4cVdF9vs/RRU+3M5Nh7cZEwOnw9CBSdGWvIDN8lmRsoqZh4
tSOPXQ9oSAHp0pe3NQvWtIH+EKT3crBcKAbtBn/oHaKAeCFYbludMGOBIMiQ5iqR
54hYSYOKi39JpqyJUvnc3NzvVfz+3RhxiD/MLddjbQKBgQDZeOMJHi6nQ+oFHtaa
6QDviM6HHDrHnDOzS1Ruq3MYxvQTrM0jrnHqx99OypHFLhB3t1PbD+CcNB9vVoVR
eLulTlGCELJP7tnyuh7BJw9zJdK3bPbsuf3id1OQkAf39oJWoH3A2okiMyDy5gCC
7UORBRVPSSGIcTp78JWCw+5EvwKBgQD8+NO9Bl38R5WztehoC8FLEfxwJ2heXKmI
A8pBjzbF+pkY/tM8mmqgpbAnp7J7zI+gYQT6APeQBbfgMH14qUQD+mbCY8jQLm4Y
A1paTGbyQST+oCA9VfIzWVJLIKDjZor5sVZ1KFgI7ZCiPTZJ3/YrV/khdA9vHkPP
USngD+u3lQKBgFxm1uCa6Gu9mYOPdNPhSLp+QHJ79iW2Iul9imRziLXwYuixNYCB
sHl3b1SFEabcSbb0ODcN6fu00d52vrK9P82fF1bSTVFVRVmy5zpepFviqEOzkr9G
z68X0HPOHvSm0v6Htqbos/fKDafnPjRjJ6BIrqM/iXX11kmvEXe8VFL1AoGBANLW
G7sWPGzPyMAf41QcP/xuQCPFZGII/q7C4eYkE3WL999yOuHunOHJVfim9sXhZu83
DSvEdJBPg8HRCDHxeSOLpetruOlxWQagfMR3mvFbRBcHo/ca06LiVgkRZ6Y/R6L1
n2ZDuqOuQ/ZD6CRICeZ0CspL7bUh10hJkAoTmtTFAoGBALKkqAS53PkdyOht9FiY
s/FjYxXWPbHFRlgt3FQ2BdJ6TwOmqjt7rEYgh+cg5dzIhoo4qeJFAv3nCYRRQ0DC
+yPEvRIRDYBcwF2MeGqpJcF3xe261y96g9wYe8ZyDgA5XMgTrNbhQ+oB1BaAGPza
FJPoN/LHUij1/uxqbJaC8Wl1
-----END PRIVATE KEY-----"""
_certificate = b"""-----BEGIN CERTIFICATE-----
MIICqjCCAZKgAwIBAgIUK6+7nU9Pfq/630DzjBGJBk2Ou5MwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMzAzMDgwNTQyMTZaFw0yMzAzMDkwNTQy
MTZaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDW5mB4IVP4ASCrPKW5vQLAeqDRnpqepjvyqs9rByTNENBzvUUni1jHGAmm
mT0QweFYaIW7n2CPynN4PJRfmdI2Qkj8w6im0NYKGUYoyKy9XC8WMBqKEFBsFt/B
yfJYtZncjPYpvBR3jQbZft2FeqNQmUv6GXQA5ul/IifmYnWuDguzlzJklfejOD3Y
wadMxt7TnMPGxtBpA7IAicheLTFu25GL+KQmOJ5/aaGRgS821SwKAAGAXBvUTAa6
swREhaxx8eo0qg1B/bJa4BnuMj5y2nxAe1CbiQcOJg09NQcRQFtjBIlr3B6kCLDs
DfSJffL1sIiHo8tgAtFaDwupJ4wrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGqx
yDVtwbfJd0XkWJYq/6jcydDNIrKi7Z290scwJrF+efXoOdFoJnrFj7BylGaClRME
iI7Xs183kYHVXYjl273Cjw+L/7g51rs1036FCIBtJfYnsCr8VALBOIDgi3UdGDZ9
/nP3YroMSQePbhhVRRrvQZYlvLintqGKyjPgvPKByhknCkTiSs+Dj2D5LoEJVekh
z6NdiPcDEOLujFkGpO/I2xDleA8BMcLrNb06Gyww9MWco7I0pK+uNwmIFdF9LSG5
bzeBEFXommCmyQDDcs1O32twy9RLKzzpWL1yPEHCn8Q91PZ4ZIPqClG/5rOywNS8
idRhwhpoRZiQXF3im5k=
-----END CERTIFICATE-----"""

_cert_obj = load_pem_x509_certificate(_certificate)
_cert_der = base64.b64encode(_cert_obj.public_bytes(Encoding.DER))


_dv_1 = b"NFs8b1MQyPBg2GKFQcVNRbhl/ls="
_sig_1 = b"ZPVR07+ggysYS7lukbteIZA9/3LgdAMpciTxbQc4K+OH1mtXdZ2DX09jqebYf3kdX3t4hpUEGH2w6Xf4LtYENnWpTsmPd86zCXZHkLSwrt+rB/dYMF2aUeDPes2EBEg+f3NMs5eR57VB6t497DVOWpPquaTPKRu1c/RnxIFURCe3vabdr9vwGPeuvlvhSBUdT3+2cED0K/i+AF/q9kNqXv81MdfWMyQmulfmH+UxHvP6oRv1sgyG+RPFiU7fUpBAbM2HTNmQugePhT/kU+62A7Sp1aAMzooH138fTrOwEsGhjzpcPIDkEW49esyerwmnbPWv7brUvb5QRoLLTCOokQ=="
_dv_256 = b"KeOO+93WmuoCL8Ci/llQH18tFfzI81ihpZCiJv0q8EI="
_sig_256 = b"P1ujK3K+c5TzaSYUVBpHrGgkZmdCSqmDB8aNKV+waTFz2s1A6wtHcrB2Hg2aam/nph8QltKY76yFBNg9E5Xzb47hsX3nssAIy2BFtYFOODVRlxCyY/Mx3OyKijg8GK3w0hsQ0raPcUfhUjGMF+na1J044V5UbeLFi0RsRRPW06PKDtYU4v/ygUmH0YBSrhHgDXBWsq4xhrKefCkeGmSD8cK+16Byg8GdgrbH0KhHEcrjwPjB1G/shsITeVARLg86FvD2eeiTII7nnBSlPxwwoe8xEAaliMW1GSj2PCx8ZVQ7tlzeS6CFmFVh5gBO+lIBW2/36Q9eqkuc0cIsg3WfDw=="

_signed = lambda cert, sig, dv, sma, dma: (
    b'<test:root xmlns:test="urn:test">'
    b'<test:signed ID="test">'
    b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b"<ds:SignedInfo>"
    b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
    b'<ds:SignatureMethod Algorithm="' + sma + b'"></ds:SignatureMethod>'
    b'<ds:Reference URI="#test">'
    b"<ds:Transforms>"
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
    b"</ds:Transforms>"
    b'<ds:DigestMethod Algorithm="' + dma + b'"></ds:DigestMethod>'
    b"<ds:DigestValue>" + dv + b"</ds:DigestValue>"
    b"</ds:Reference>"
    b"</ds:SignedInfo>"
    b"<ds:SignatureValue>" + sig + b"</ds:SignatureValue>"
    b"<ds:KeyInfo>"
    b"<ds:X509Data>"
    b"<ds:X509Certificate>" + cert + b"</ds:X509Certificate>"
    b"</ds:X509Data>"
    b"</ds:KeyInfo>"
    b"</ds:Signature>"
    b"<test:content>Value</test:content>"
    b"</test:signed>"
    b"</test:root>"
)

_verify_config = VerifyConfig(
    allowed_digest_method={hashes.SHA1, hashes.SHA256},
    allowed_signature_method={hashes.SHA1, hashes.SHA256},
)


def _pretty_b64(val: bytes) -> bytes:
    return b"\n".join(map(str.encode, textwrap.wrap(val.decode(), width=79)))


@dataclass
class AlgorithmConfig:
    sma_uri: bytes
    dma_uri: bytes
    sv: bytes
    dv: bytes


_values = {
    (1, 1): AlgorithmConfig(
        b"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        b"http://www.w3.org/2000/09/xmldsig#sha1",
        b"ZPVR07+ggysYS7lukbteIZA9/3LgdAMpciTxbQc4K+OH1mtXdZ2DX09jqebYf3kdX3t4hpUEGH2w6Xf4LtYENnWpTsmPd86zCXZHkLSwrt+rB/dYMF2aUeDPes2EBEg+f3NMs5eR57VB6t497DVOWpPquaTPKRu1c/RnxIFURCe3vabdr9vwGPeuvlvhSBUdT3+2cED0K/i+AF/q9kNqXv81MdfWMyQmulfmH+UxHvP6oRv1sgyG+RPFiU7fUpBAbM2HTNmQugePhT/kU+62A7Sp1aAMzooH138fTrOwEsGhjzpcPIDkEW49esyerwmnbPWv7brUvb5QRoLLTCOokQ==",
        b"NFs8b1MQyPBg2GKFQcVNRbhl/ls=",
    ),
    (1, 256): AlgorithmConfig(
        b"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        b"http://www.w3.org/2001/04/xmlenc#sha256",
        b"loMxA3k3/8fXT10omi0U5kInJGmqpR4n7W25SqGK6mD5cvs+mhSDYOeQuhFWiF92J4l2enO5yMiEAW0F7XRmIMDVjl9p3nwMrkPGurRT52ycCAb5ycGp15ooOV8M+tsJRuyp73hLnbHmK26VZtkQMunmgJDIlBxoYdPSfjdEl8k+AujpEokT/iyQ9CobPjsO7RfGn6bJNpxTZo/HlkhKF07oYbqWrci2AXUn4/18bur6hXbdfbmGfBfFxYZKuoaB1CFKAfIAmxMIEBNluGxNsYyEx5hE78X/97j1popW6lRv4h5GsBqNxlITbpRonVKreLxPcsHMYo2lT2GeUym1Cg==",
        b"KeOO+93WmuoCL8Ci/llQH18tFfzI81ihpZCiJv0q8EI=",
    ),
    (256, 1): AlgorithmConfig(
        b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        b"http://www.w3.org/2000/09/xmldsig#sha1",
        b"isEnIga7ISY+sR9AaR3xJFqtDTMVX9OpNNOT7xqMekMFTkpHQtL6Hgik4CQdM86B1TGHHIcg2UIa3pqQnUxRfSx0/PK7mSYKeCvshrOHCHpnaP4ZkdLCPunYfrVG1Z/VvJobdqtDR84TQQNnNF+GOrvgtg7MWeHg+ZqRGQpW4x1Ose3VKCi2PKh8fq/zeH2K8kmft4iLWakYPwAW3hlLurw2Z8Fo/ULZqLxmC9ZOWAyOjeDhSYngnPPO3A0QUC2f6Z87zJFel7Y86iM5UcRerIp0AjuGOKBfnBX+dOyY12ixd/YEwEmnkyLocqG+5sZ/ezMBRGcUaUIalQN3TxLBsA==",
        b"NFs8b1MQyPBg2GKFQcVNRbhl/ls=",
    ),
    (256, 256): AlgorithmConfig(
        b"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        b"http://www.w3.org/2001/04/xmlenc#sha256",
        b"P1ujK3K+c5TzaSYUVBpHrGgkZmdCSqmDB8aNKV+waTFz2s1A6wtHcrB2Hg2aam/nph8QltKY76yFBNg9E5Xzb47hsX3nssAIy2BFtYFOODVRlxCyY/Mx3OyKijg8GK3w0hsQ0raPcUfhUjGMF+na1J044V5UbeLFi0RsRRPW06PKDtYU4v/ygUmH0YBSrhHgDXBWsq4xhrKefCkeGmSD8cK+16Byg8GdgrbH0KhHEcrjwPjB1G/shsITeVARLg86FvD2eeiTII7nnBSlPxwwoe8xEAaliMW1GSj2PCx8ZVQ7tlzeS6CFmFVh5gBO+lIBW2/36Q9eqkuc0cIsg3WfDw==",
        b"KeOO+93WmuoCL8Ci/llQH18tFfzI81ihpZCiJv0q8EI=",
    ),
}


@pytest.fixture(scope="session", params=itertools.product([1, 256], [1, 256]), ids=repr)
def algorithm_config(request) -> AlgorithmConfig:
    return _values[request.param]


@pytest.fixture(scope="session", params=[True, False])
def cert_and_signed(algorithm_config, request) -> Tuple[Certificate, bytes]:
    transform = _pretty_b64 if request.param else lambda x: x
    return _cert_obj, _signed(
        transform(_cert_der),
        transform(algorithm_config.sv),
        algorithm_config.dv,
        algorithm_config.sma_uri,
        algorithm_config.dma_uri,
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

    verified_element = extract_verified_element(
        xml=xml,
        certificate=cert,
        config=_verify_config,
    )
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
        extract_verified_element(xml=broken, certificate=cert, config=_verify_config)


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


def test_verify_fails_with_different_certificate(key_and_cert, key_factory):
    ns = ElementMaker(namespace="urn:test", nsmap={"test": "urn:test"})
    element_to_sign = ns.signed(ns.content("Value"), ID="test")
    ns.root(element_to_sign)
    signed_data = sign(
        element=element_to_sign,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
    )
    _, other = key_factory()
    with pytest.raises(CertificateMismatch):
        extract_verified_element(xml=signed_data, certificate=other)


def test_double_signature_fails(key_and_cert):
    element = E.tag("Value", ID="Test")
    signed_data = sign(
        element=element,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
    )
    element = utils.deserialize_xml(signed_data)
    signed_data = sign(
        element=element,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
    )
    with pytest.raises(MultipleElementsFound):
        extract_verified_element(xml=signed_data, certificate=key_and_cert.certificate)


def test_double_reference_fails(key_and_cert):
    target = E.tag("Target", ID="same")
    E.root(target, E.tag("Other", ID="same"))
    signed_data = sign(
        element=target,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
    )
    with pytest.raises(MultipleElementsFound):
        extract_verified_element(xml=signed_data, certificate=key_and_cert.certificate)


def test_verification_failed(cert_and_signed):
    cert, xml = cert_and_signed
    root = utils.deserialize_xml(xml)
    signature_value = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
    signature_value.text = "YWFh" + signature_value.text
    xml = utils.serialize_xml(root)
    with pytest.raises(VerificationFailed):
        extract_verified_element(xml=xml, certificate=cert, config=_verify_config)


def test_verification_failed2(cert_and_signed):
    cert, xml = cert_and_signed
    root = utils.deserialize_xml(xml)
    signature_value = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
    signature_value.text = signature_value.text + "x"
    xml = utils.serialize_xml(root)
    with pytest.raises(binascii.Error):
        extract_verified_element(xml=xml, certificate=cert, config=_verify_config)


def test_extract_verified_element_and_certificate(cert_and_signed, key_factory):
    _, incorrect_cert = key_factory()
    correct_cert, xml = cert_and_signed

    verified_element, used_certificate = extract_verified_element_and_certificate(
        xml=xml,
        certificates={incorrect_cert, correct_cert},
        config=_verify_config,
    )
    assert used_certificate == correct_cert
    assert verified_element is not None
    assert verified_element.tag == "{urn:test}signed"
    assert verified_element.attrib["ID"] == "test"


def test_extract_verified_element_and_certificate_fail(cert_and_signed, key_factory):
    _, incorrect_cert = key_factory()
    correct_cert, xml = cert_and_signed

    with pytest.raises(CertificateMismatch) as exc:
        extract_verified_element_and_certificate(
            xml=xml, certificates={incorrect_cert}, config=_verify_config
        )
    assert exc.value.received_certificate == correct_cert
    assert exc.value.expected_certificates == {incorrect_cert}
