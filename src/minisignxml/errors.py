from collections.abc import Collection

from cryptography.x509 import Certificate


class MiniSignXMLError(Exception):
    pass


class VerificationFailed(MiniSignXMLError):
    pass


class CertificateMismatch(MiniSignXMLError):
    received_certificate: Certificate
    expected_certificates: Collection[Certificate]

    def __init__(
        self,
        received_certificate: Certificate,
        expected_certificates: Collection[Certificate],
    ):
        self.received_certificate = received_certificate
        self.expected_certificates = expected_certificates
        super().__init__()


class UnsupportedHasher(MiniSignXMLError):
    pass


class UnsupportedAlgorithm(MiniSignXMLError):
    pass


class ElementNotFound(MiniSignXMLError):
    pass


class MultipleElementsFound(MiniSignXMLError):
    pass


class NoIDAttribute(MiniSignXMLError):
    pass
