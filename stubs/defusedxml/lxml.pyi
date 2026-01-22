from lxml.etree import XMLParser, _Element

def fromstring(
    text: str | bytes,
    parser: XMLParser = ...,
    base_url: str | bytes = ...,
    forbid_dtd: bool = ...,
    forbid_entities: bool = ...,
) -> _Element: ...
