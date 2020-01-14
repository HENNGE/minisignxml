from lxml.builder import ElementMaker

from minisignxml.config import SigningConfig
from minisignxml.internal import utils
from minisignxml.sign import sign
from minisignxml.verify import verify


def test_pysign_verified_by_xmlsec1(xmlsec1, key_and_cert, tmp_path):
    ns = ElementMaker(namespace="urn:test", nsmap={"test": "urn:test"})
    signed = ns.signed(ns.content("Value"), ID="test")
    ns.root(signed)
    config = SigningConfig.default()
    signed_document = sign(
        element=signed,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
        config=config,
    )
    path = tmp_path / "signed.xml"
    with path.open("wb") as fobj:
        fobj.write(signed_document)
    priv_pem, cert_pem = key_and_cert.files()
    xmlsec1(
        "verify", "--pubkey-cert-pem", cert_pem, "--id-attr:ID", "signed", str(path)
    )


def test_roundtrip(key_and_cert):
    ns = ElementMaker(namespace="urn:test", nsmap={"test": "urn:test"})
    element_to_sign = ns.signed(ns.content("Value"), ID="test")
    ns.root(element_to_sign)
    unsigned_data = utils.serialize_xml(element_to_sign)
    config = SigningConfig.default()
    signed_data = sign(
        element=element_to_sign,
        private_key=key_and_cert.private_key,
        certificate=key_and_cert.certificate,
        config=config,
    )
    verified = verify(xml=signed_data, certificate=key_and_cert.certificate)
    verified_data = utils.serialize_xml(verified)
    assert unsigned_data == verified_data
