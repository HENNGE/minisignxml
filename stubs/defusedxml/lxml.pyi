from typing import Union

from lxml.etree import XMLParser, _Element

def fromstring(
    text: Union[str, bytes],
    parser: XMLParser = ...,
    base_url: Union[str, bytes] = ...,
    forbid_dtd: bool = ...,
    forbid_entities: bool = ...,
) -> _Element: ...
