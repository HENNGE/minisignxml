import base64
from typing import List, Mapping

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.x509 import Certificate
from defusedxml.lxml import fromstring
from lxml.etree import _Element as Element, tostring

from ..errors import (
    ElementNotFound,
    MultipleElementsFound,
    UnsupportedAlgorithm,
    UnsupportedHasher,
)
from .constants import *
from .namespaces import NAMESPACE_MAP


def hash_digest(algorithm: HashAlgorithm, data: bytes) -> bytes:
    h = hashes.Hash(algorithm, default_backend())
    h.update(data)
    return h.finalize()


def signature_method_algorithm(hasher: HashAlgorithm) -> str:
    if isinstance(hasher, hashes.SHA1):
        return XMLDSIG_RSA_SHA1
    elif isinstance(hasher, hashes.SHA256):
        return XMLDSIG_RSA_SHA256
    else:
        raise UnsupportedHasher(hasher)


def signature_method_hasher(algorithm: str) -> HashAlgorithm:
    if algorithm == XMLDSIG_SHA1:
        return hashes.SHA1()
    elif algorithm == XMLDSIG_RSA_SHA256:
        return hashes.SHA256()
    else:
        raise UnsupportedAlgorithm(algorithm)


def digest_method_algorithm(hasher: HashAlgorithm) -> str:
    if isinstance(hasher, hashes.SHA1):
        return XMLDSIG_SHA1
    elif isinstance(hasher, hashes.SHA256):
        return XMLENC_SHA256
    else:
        raise UnsupportedHasher(hasher)


def digest_method_hasher(algorithm: str) -> HashAlgorithm:
    if algorithm == XMLDSIG_SHA1:
        return hashes.SHA1()
    elif algorithm == XMLENC_SHA256:
        return hashes.SHA256()
    else:
        raise UnsupportedAlgorithm(algorithm)


def ascii_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def deserialize_xml(xml: bytes) -> Element:
    return fromstring(xml)


def serialize_xml(element: Element) -> bytes:
    xml = tostring(element, method="c14n", exclusive=True)
    assert isinstance(xml, bytes)
    return xml


def find_or_raise(
    element: Element, path: str, ns_map: Mapping[str, str] = NAMESPACE_MAP
) -> Element:
    return exactly_one(element.findall(path, ns_map), path, element)


def exactly_one(elements: List[Element], path: str, parent: Element) -> Element:
    num_results = len(elements)
    if num_results < 1:
        raise ElementNotFound(path, parent)
    elif num_results > 1:
        raise MultipleElementsFound(path, parent)
    return elements[0]


def sign(data: bytes, key: RSAPrivateKey, hasher: HashAlgorithm) -> bytes:
    return key.sign(data, padding.PKCS1v15(), hasher)


def verify(
    signature: bytes, data: bytes, certificate: Certificate, hasher: HashAlgorithm
) -> None:
    key = certificate.public_key()
    if not isinstance(key, RSAPublicKey):
        raise TypeError(
            f"Only certificates with RSA Keys are supported. Got {key!r} instead."
        )
    key.verify(signature, data, padding.PKCS1v15(), hasher)


def get_root(element: Element) -> Element:
    parent = element.getparent()
    while parent is not None:
        element, parent = parent, parent.getparent()
    return element


def remove_preserving_whitespace(element: Element) -> None:
    parent = element.getparent()
    if element.tail:
        prev = element.getprevious()
        if prev is not None:
            prev.tail = (prev.tail or "") + element.tail
        else:
            parent.text = (parent.text or "") + element.tail
    parent.remove(element)


def base64_binary_content(element: Element) -> bytes:
    return base64.b64decode(
        element.text.replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(" ", ""),
        validate=True,
    )
