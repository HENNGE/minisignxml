# minisignxml

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![CircleCI](https://circleci.com/gh/HENNGE/minisignxml.svg?style=svg)](https://circleci.com/gh/HENNGE/minisignxml)


Python library to sign and verify XML documents. 

This library, *on purpose*, only supports a limited part of the xmldsig specification. It is mainly aimed at allowing SAML documents to be signed and verified.

Supported features:

* Simple API.
* Only support enveloped signatures (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`)
* Require and only support exclusive XML canonincalization without comments (`http://www.w3.org/2001/10/xml-exc-c14n#`)
* Support SHA-256 (default) and SHA-1 (for compatibility, not recommended) for signing and digest (`https://www.w3.org/2000/09/xmldsig#sha1`, `https://www.w3.org/2000/09/xmldsig#rsa-sha1`, `http://www.w3.org/2001/04/xmlenc#sha256`, `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
* Only support X509 certificates and RSA private keys
* Uses `lxml` for XML handling and `cryptography` for cryptography.
* Only supports a single signature, with a single reference in a document.

`minisignxml` performs no IO and you have to manage and load the keys/certificates yourself.

## API

### Signing

`minisignxml.sign.sign`

```python
def sign(
    *,
    element: Element,
    private_key: RSAPrivateKey,
    certificate: Certificate,
    config: SigningConfig = SigningConfig.default(),
    index: int = 0
) -> bytes:
```

Signs the given `lxml.etree._Element` with the given `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` private key, embedding the `cryptography.x509.Certificate` in the signature. Use `minisignxml.config.SigningConfig` to control the hash algorithms uses (default is SHA-256). The `index` controls at which index the signature element is appended to the element.

If the `element` passed in does not have an `ID` attribute, one will be set automatically. It is the callers responsibility to ensure the `ID` attribute of the `Element` is unique for the whole document.

Returns `bytes` containing the serialized XML including the signature. 

#### SigningConfig

`minisignxml.config.SigningConfig` is a `dataclass` with the following fields:

* `signature_method`: A `cryptography.hazmat.primitives.hashes.HashAlgorithm` to use for the signature. Defaults to an instance of `cryptography.hazmat.primitives.hashes.SHA256`.
* `digest_method`: A `cryptography.hazmat.primitives.hashes.HashAlgorithm` to use for the content digest. Defaults to an instance of `cryptography.hazmat.primitives.hashes.SHA256`.


### Verifying

`minisignxml.verify.extract_verified_element`

```python
def extract_verified_element(
    *, 
    xml: bytes, 
    certificate: Certificate,  
    config: VerifyConfig=VerifyConfig.default()
) -> Element:
```

Verifies that the XML document given (as bytes) is correctly signed using the private key of the `cryptography.x509.Certificate` provided. 

A successful call to `extract_verified_element` does not guarantee the integrity of the whole document passed to it via the `xml` parameter. Only the sub-tree returned from the function has been verified. The caller should use the returned `lxml.etree._Element` for further processing.

Raises an exception (see `minisignxml.errors`, though other exceptions such as `ValueError`, `KeyError` or others may also be raised) if the verification failed. Otherwise returns the signed `lxml.etree._Element` (not necessarily the whole document passed to `extract_verified_element`), with the signature removed.

You can control the allowed signature and digest method by using a custom `VerifyConfig` instance. By default only SHA-256 is allowed.

#### VerifyConfig

`minisignxml.config.SigningConfig` is a `dataclass` with the following fields:

* `allowed_signature_methods`: A container of `cryptography.hazmat.primitives.hashes.HashAlgorithm` types to allow for signing. Defaults to `{cryptography.hazmat.primitives.hashes.SHA256}`.
* `allowed_digest_methods`: A container of `cryptography.hazmat.primitives.hashes.HashAlgorithm` types to allow for the content digest. Defaults to `{cryptography.hazmat.primitives.hashes.SHA256}`.
