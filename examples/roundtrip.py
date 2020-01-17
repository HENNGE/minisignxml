import datetime
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, NameOID
from lxml.builder import E

from minisignxml.internal.utils import serialize_xml
from minisignxml.sign import sign
from minisignxml.verify import extract_verified_element


def roundtrip():
    """
    Create a super simple XML document:
        <tag ID='hoge'>Value</tag>
    Then sign that tag with a randomly generated key/cert pair.
    Then verify the resulting signed document.
    """
    key, cert = make_key_and_cert()
    element = E.tag("Value", ID="hoge")
    print("Unsigned:")
    print(serialize_xml(element).decode("utf-8"))
    signed = sign(element=element, private_key=key, certificate=cert)
    print("=" * 70)
    print("Signed:")
    print(signed.decode("utf-8"))
    verified = extract_verified_element(xml=signed, certificate=cert)
    print("=" * 70)
    print("Verified:")
    print(serialize_xml(verified).decode("utf-8"))


def make_key_and_cert() -> Tuple[RSAPrivateKey, Certificate]:
    """
    Create a private key/certificate pair. In real code you would usually
    generate these once and then securely store them somewhere.
    """
    backend = default_backend()
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=backend
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256(), backend)
    )
    return key, cert


if __name__ == "__main__":
    roundtrip()
