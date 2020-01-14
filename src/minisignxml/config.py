from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class SigningConfig:
    signature_method: hashes.HashAlgorithm
    digest_method: hashes.HashAlgorithm

    @classmethod
    def default(cls) -> SigningConfig:
        return cls(signature_method=hashes.SHA256(), digest_method=hashes.SHA256(),)
