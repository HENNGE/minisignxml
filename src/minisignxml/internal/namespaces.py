from lxml.builder import ElementMaker

from .constants import *


def make_namespace(prefix: str, urn: str) -> ElementMaker:
    return ElementMaker(namespace=urn, nsmap={prefix: urn})


ds = make_namespace("ds", XMLDSIG)

NAMESPACE_MAP = {"ds": XMLDSIG, "c14n": XML_EXC_C14N}
