class XMLSigningError(Exception):
    pass


class VerificationFailed(XMLSigningError):
    pass


class CertificateMismatch(XMLSigningError):
    pass


class UnsupportedHasher(XMLSigningError):
    pass


class UnsupportedAlgorithm(XMLSigningError):
    pass


class ElementNotFound(XMLSigningError):
    pass


class MultipleElementsFound(XMLSigningError):
    pass
