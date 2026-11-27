# xmlseclibs 3.1.5 signature fixtures

These files were signed by **xmlseclibs 3.1.5** (`robrichards/xmlseclibs` 3.1.5, git `03062be78178cbb5e8f605cd255dc32a14981f92`). Do not regenerate them with the current library.

They were produced in a scratch install outside this repository:

```
composer require robrichards/xmlseclibs:3.1.5
```

The certificate was created with OpenSSL 3.0.13:

```
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout fixture.key -out cert.pem \
  -subj "/CN=xmlseclibs-3.1.5-fixture" -days 3650
```

Each document (`<Root xmlns="urn:xmlseclibs-3.1.5"><Item>payload</Item></Root>`) was signed with that 3.1.5 install only:

- exclusive canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- enveloped-signature transform
- empty Reference URI
- SignatureMethod `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`
- DigestMethod `sha256` in `rsa-sha256-sha256.xml`, or `sha1` in `rsa-sha256-sha1.xml`
- the X.509 certificate embedded in KeyInfo

The signing key is not in this repository. Verification uses `cert.pem`.
