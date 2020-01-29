from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate
from lxml.etree import _Element as Element

from .config import SigningConfig
from .errors import NoIDAttribute
from .internal import utils
from .internal.constants import *
from .internal.namespaces import ds

__all__ = ("sign",)


def sign(
    *,
    element: Element,
    private_key: RSAPrivateKey,
    certificate: Certificate,
    config: SigningConfig = SigningConfig.default(),
    index: int = 0,
) -> bytes:
    try:
        element_id = element.attrib["ID"]
    except KeyError:
        raise NoIDAttribute(element)
    # Generate the digest value of the element/content to be signed
    content_digest_value = utils.ascii_b64(
        utils.hash_digest(config.digest_method, utils.serialize_xml(element))
    )
    # Build the SignedInfo tag, referencing the element we got passed,
    # including the digest value we just created.
    signed_info = ds.SignedInfo(
        ds.CanonicalizationMethod(Algorithm=XML_EXC_C14N),
        ds.SignatureMethod(
            Algorithm=utils.signature_method_algorithm(config.signature_method)
        ),
        ds.Reference(
            ds.Transforms(
                ds.Transform(Algorithm=XMLDSIG_ENVELOPED_SIGNATURE),
                ds.Transform(Algorithm=XML_EXC_C14N),
            ),
            ds.DigestMethod(
                Algorithm=utils.digest_method_algorithm(config.digest_method)
            ),
            ds.DigestValue(content_digest_value),  # Embed the digest value
            URI="#" + element_id,  # Reference the element to sign
        ),
    )
    # Sign the digest of the SignedInfo element
    signature = utils.sign(
        utils.serialize_xml(signed_info), private_key, config.signature_method
    )
    signature_value = utils.ascii_b64(signature)
    # Encode the certificate to embed into the signature.
    cert_data = utils.ascii_b64(certificate.public_bytes(Encoding.DER))
    signature_element = ds.Signature(
        signed_info,
        ds.SignatureValue(signature_value),
        ds.KeyInfo(ds.X509Data(ds.X509Certificate(cert_data))),
    )
    element.insert(index, signature_element)
    root = utils.get_root(element)
    result = utils.serialize_xml(root)
    element.remove(signature_element)
    return result
