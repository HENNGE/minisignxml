class MiniSignXMLError(Exception):
    pass


class VerificationFailed(MiniSignXMLError):
    pass


class CertificateMismatch(MiniSignXMLError):
    pass


class UnsupportedHasher(MiniSignXMLError):
    pass


class UnsupportedAlgorithm(MiniSignXMLError):
    pass


class ElementNotFound(MiniSignXMLError):
    pass


class MultipleElementsFound(MiniSignXMLError):
    pass
