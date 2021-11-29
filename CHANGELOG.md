# Changelog

## 21.11

* Fixed handling of base64 encoded binary data in signatures.
* Updated minimum cryptography version to 35

## 20.11b0

* Added `minisignxml.verify.extract_verified_element_and_certificate` to allow specifying multiple certificates when verifying elements to aid certificate rollover.
* `minisignxml.errors.CertificateMismatch` now stores the received certificate and the expected certificates.

## 20.8b0

* Fixed lxml version selector being too strict.

## 20.7b0

* Initial release
