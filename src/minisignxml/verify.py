import base64
from hmac import compare_digest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Certificate, load_der_x509_certificate
from lxml.etree import XPath, _Element as Element

from .config import VerifyConfig
from .errors import CertificateMismatch, UnsupportedAlgorithm, VerificationFailed
from .internal import utils
from .internal.constants import XML_EXC_C14N, XMLDSIG_ENVELOPED_SIGNATURE
from .internal.namespaces import NAMESPACE_MAP

__all__ = ("extract_verified_element",)


def extract_verified_element(
    *,
    xml: bytes,
    certificate: Certificate,
    config: VerifyConfig = VerifyConfig.default(),
) -> Element:
    tree = utils.deserialize_xml(xml)
    signature = utils.find_or_raise(tree, ".//ds:Signature")
    signed_info = utils.find_or_raise(signature, "./ds:SignedInfo")
    signature_method = utils.find_or_raise(signed_info, "./ds:SignatureMethod")
    signature_value = utils.find_or_raise(signature, "./ds:SignatureValue")
    key_info = utils.find_or_raise(signature, "./ds:KeyInfo/ds:X509Data")
    xml_cert = load_der_x509_certificate(
        base64.b64decode(key_info.text), default_backend()
    )
    if xml_cert != certificate:
        raise CertificateMismatch()
    c14n_method = utils.find_or_raise(signed_info, "ds:CanonicalizationMethod")
    if c14n_method.attrib["Algorithm"] != XML_EXC_C14N:
        raise UnsupportedAlgorithm(c14n_method.attrib["Algorithm"])
    signature_hasher = utils.signature_method_hasher(
        signature_method.attrib["Algorithm"]
    )
    if not isinstance(signature_hasher, tuple(config.allowed_signature_method)):
        raise UnsupportedAlgorithm(signature_method.attrib["Algorithm"])
    try:
        utils.verify(
            base64.b64decode(signature_value.text),
            utils.serialize_xml(signed_info),
            certificate,
            signature_hasher,
        )
    except InvalidSignature:
        raise VerificationFailed()
    reference = utils.find_or_raise(signed_info, "ds:Reference")
    reference_id = reference.attrib["URI"]
    if reference_id[0] != "#":
        raise ValueError(reference_id)
    reference_id = reference_id[1:]
    transforms = {
        transform.attrib["Algorithm"]
        for transform in utils.find_or_raise(reference, "ds:Transforms").findall(
            "./ds:Transform", NAMESPACE_MAP
        )
    }
    if transforms != {XMLDSIG_ENVELOPED_SIGNATURE, XML_EXC_C14N}:
        raise UnsupportedAlgorithm(transforms)
    digest_method = utils.find_or_raise(reference, "ds:DigestMethod").attrib[
        "Algorithm"
    ]
    digest_value = utils.find_or_raise(reference, "ds:DigestValue").text
    digest_hasher = utils.digest_method_hasher(digest_method)
    if not isinstance(digest_hasher, tuple(config.allowed_digest_method)):
        raise UnsupportedAlgorithm(digest_method)
    referenced_element = utils.exactly_one(
        XPath("descendant-or-self::*[@ID = $reference_id]")(
            tree, reference_id=reference_id
        ),
        f".//*[@ID = {reference_id!r}]",
        tree,
    )
    # remove the signature node (since it's enveloped)
    # this is both required to verify the signature and also cleans up the returned element
    signature.getparent().remove(signature)
    referenced_bytes = utils.serialize_xml(referenced_element)
    referenced_digest = utils.hash_digest(digest_hasher, referenced_bytes)
    if not compare_digest(base64.b64decode(digest_value), referenced_digest):
        raise VerificationFailed()
    return utils.deserialize_xml(referenced_bytes)
