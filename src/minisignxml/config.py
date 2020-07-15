from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Type

from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class SigningConfig:
    signature_method: hashes.HashAlgorithm
    digest_method: hashes.HashAlgorithm

    @classmethod
    def default(cls) -> SigningConfig:
        return cls(signature_method=hashes.SHA256(), digest_method=hashes.SHA256())


@dataclass(frozen=True)
class VerifyConfig:
    allowed_signature_method: Collection[Type[hashes.HashAlgorithm]]
    allowed_digest_method: Collection[Type[hashes.HashAlgorithm]]

    @classmethod
    def default(cls) -> VerifyConfig:
        return cls(
            allowed_signature_method={hashes.SHA256},
            allowed_digest_method={hashes.SHA256},
        )
