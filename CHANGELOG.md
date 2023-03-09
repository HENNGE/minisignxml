# Changelog

## 22.8

* Add support for alternative attributes for signing and verifying.

## 22.4.1

* Fix packaging error

## 22.4 (yanked)

* Fixed SHA1 algorithm URIs

## 20.11b0

* Added `minisignxml.verify.extract_verified_element_and_certificate` to allow specifying multiple certificates when verifying elements to aid certificate rollover.
* `minisignxml.errors.CertificateMismatch` now stores the received certificate and the expected certificates.

## 20.8b0

* Fixed lxml version selector being too strict.

## 20.7b0

* Initial release
