import datetime
import shutil
from dataclasses import dataclass
from pathlib import Path
from subprocess import check_output
from typing import Callable, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509 import Certificate, NameOID
from lxml.etree import Element

from minisignxml.config import SigningConfig
from minisignxml.internal import utils
from minisignxml.internal.constants import *
from minisignxml.internal.namespaces import ds


@pytest.fixture
def xmlsec1():
    path = shutil.which("xmlsec1") or shutil.which("xmlsec1.exe")
    if not path:
        raise pytest.skip("xmlsec1 not found")

    def execute(*args):
        return check_output((path,) + args)

    return execute


@dataclass(frozen=True)
class KeyAndCert:
    tmp_path: Path
    private_key: RSAPrivateKeyWithSerialization
    certificate: Certificate

    def files(self) -> Tuple[str, str]:
        pk_pem_path = self.tmp_path / "pk.pem"
        cert_pem_path = self.tmp_path / "cert.pem"
        with pk_pem_path.open("wb") as fobj:
            fobj.write(
                self.private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                )
            )
        with cert_pem_path.open("wb") as fobj:
            fobj.write(self.certificate.public_bytes(Encoding.PEM))
        return str(pk_pem_path), str(cert_pem_path)


@pytest.fixture
def key_and_cert(tmp_path) -> KeyAndCert:
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
    return KeyAndCert(tmp_path, key, cert)


@pytest.fixture
def signature_template() -> Callable[[SigningConfig], Element]:
    def builder(
        *, config: SigningConfig, certificate: Certificate, element_id: str
    ) -> Element:
        return ds.Signature(
            ds.SignedInfo(
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
                    ds.DigestValue(),
                    URI="#" + element_id,
                ),
            ),
            ds.SignatureValue(),
            ds.KeyInfo(
                ds.X509Data(utils.ascii_b64(certificate.public_bytes(Encoding.DER)))
            ),
        )

    return builder
