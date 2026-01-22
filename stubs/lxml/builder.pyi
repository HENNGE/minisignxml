from collections.abc import Callable
from typing import Any, Protocol

from lxml.etree import _Element

class ElementMakerProtocol(Protocol):
    def __call__(self, *children: Any, **attrib: str) -> _Element: ...

class MakeElementProtocol(Protocol):
    def __call__(
        self,
        tag: str,
        attrib: dict[str, str] | None = ...,
        nsmap: dict[str, str] | None = ...,
        **extra: Any,
    ) -> _Element: ...

class ElementMaker:
    def __init__(
        self,
        typemap: dict[Any, Callable[[_Element, Any], None]] | None = ...,
        namespace: str | None = ...,
        nsmap: dict[str, str] | None = ...,
        makeelement: MakeElementProtocol | None = ...,
    ): ...
    def __call__(self, tag: str, *children: Any, **attrib: str) -> _Element: ...
    def __getattr__(self, tag: str) -> ElementMakerProtocol: ...

E: ElementMaker
