from typing import Any, Callable, Optional, Protocol

from lxml.etree import _Element

class ElementMakerProtocol(Protocol):
    def __call__(self, *children: Any, **attrib: str) -> _Element: ...

class MakeElementProtocol(Protocol):
    def __call__(
        self,
        tag: str,
        attrib: Optional[dict[str, str]] = ...,
        nsmap: Optional[dict[str, str]] = ...,
        **extra: Any
    ) -> _Element: ...

class ElementMaker:
    def __init__(
        self,
        typemap: Optional[dict[Any, Callable[[_Element, Any], None]]] = ...,
        namespace: Optional[str] = ...,
        nsmap: Optional[dict[str, str]] = ...,
        makeelement: Optional[MakeElementProtocol] = ...,
    ): ...
    def __call__(self, tag: str, *children: Any, **attrib: str) -> _Element: ...
    def __getattr__(self, tag: str) -> ElementMakerProtocol: ...

E: ElementMaker
