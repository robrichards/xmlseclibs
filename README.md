#xmlseclibs 

xmlseclibs is a library written in PHP for working with XML Encryption and Signatures.

The author of xmlseclibs is Rob Richards.

# Branches
Master is currently the only actively maintained branch.
* master: requires PHP version 8.3+
* 3.1: Added AES-GCM support requiring 7.1+
* 3.0: Removes mcrypt usage requiring 5.4+ (5.6.24+ recommended for security reasons)
* 2.0: Contains namespace support requiring 5.3+
* 1.4: Contains auto-loader support while also maintaining backwards compatiblity with the older 1.3 version using the xmlseclibs.php file. Supports PHP 5.2+

# Requirements

xmlseclibs requires PHP version 8.3 or greater and phpseclib 3.0.58 or later. OpenSSL is optional (phpseclib is used for crypto).

## Security notes

* Prefer the safe-by-default verifier `verifyDocument()` (see below). It requires a caller-supplied (pinned) key, never derives the key from the document's `KeyInfo`, enforces an algorithm allowlist for both the `SignatureMethod` and every `DigestMethod`, and only reports success when every reference validated. It returns the validated nodes for you to operate on.
* If you use the low-level primitives directly, always check verification with a strict comparison: `$objDSig->verify($key) === 1`. A return of `-1` is an error and is truthy in boolean context.
* After `validateReference()`, use `getValidatedNodes()` and operate only on those nodes (especially for SAML / WS-Security). Do not re-select assertions by Id from the whole document.
* Do not trust a signing certificate from `KeyInfo` alone. Load and pin trusted keys yourself.
* Signature verification (`verifyDocument()` as well as `verify()` / `validateReference()`) accepts by default only SHA-256/384/512 digests and RSA-SHA-256/384/512 (and RSA-PSS) and ECDSA-SHA-256/384/512 signatures (`$objDSig->allowedSignatureAlgorithms` / `$objDSig->allowedDigestAlgorithms` default to `XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS` / `DEFAULT_DIGEST_ALGORITHMS`). To accept SHA-1 (rsa-sha1, dsa-sha1, hmac-sha1 and sha1 digests), call `$objDSig->enableLegacyMode()` or widen the lists explicitly, e.g. `$objDSig->allowedSignatureAlgorithms[] = XMLSecurityKey::RSA_SHA1;` and `$objDSig->allowedDigestAlgorithms[] = XMLSecurityDSig::SHA1;`. In `verifyDocument()`, a null list falls back to the corresponding default for that call and the property is restored afterwards (null stays null). Callers that need an extra algorithm (for example SHA-1 digests) should add it to the list explicitly. The low-level methods `verify()` and `validateReference()` treat a null list as no restriction. Signing is unaffected. ECDSA keys are limited to the P-256, P-384 and P-521 curves (`XMLSecurityKey::EC_CURVE_OIDS`); to accept another curve, add it explicitly to `$objKey->allowedECCurves`.
* Prefer RSA-OAEP and AES-GCM for encryption. RSA-1.5 key transport is **denied by default** on decryption (Bleichenbacher risk); opt in with `$objenc->allowRSA15KeyTransport = true;` plus `$objenc->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5;` only for legacy interop. Key transport is restricted by default to RSA-OAEP (`$objenc->allowedKeyAlgorithms` defaults to `XMLSecEnc::DEFAULT_KEY_ALGORITHMS`); widen the list explicitly, or set it to `null` to apply no key-transport allowlist. Data decryption accepts only AES-GCM by default (`$objenc->allowedDataAlgorithms` defaults to `XMLSecEnc::DEFAULT_DATA_ALGORITHMS`). AES-CBC and TripleDES-CBC require `$objenc->enableLegacyMode()` (adds `XMLSecEnc::LEGACY_DATA_ALGORITHMS`) or an explicit list. Set the list to `null` to apply no data-encryption allowlist. Encryption still uses the algorithm of the caller-supplied key.
* XPath (`REC-xpath-19991116`) transforms are **rejected during verification by default**. They evaluate a document-supplied XPath expression in `validateReference()` before any signature crypto runs, so a crafted expression is a pre-authentication CPU denial-of-service — and the expression is arbitrary XPath by design, so it cannot be sanitized. SAML and WS-Security do not use them. Set `$objDSig->allowXPathTransforms = true` only if you must verify signatures that legitimately rely on XPath transforms and you trust the source. Signing is unaffected. When enabled, the count/namespace caps below still apply.

* XPath transforms (once enabled) are capped by default (`maxXPathTransforms` / `maxXPathNamespaces`, defaults 5 and 20). Raise or lower these on the `XMLSecurityDSig` instance if your use case needs different limits.
* `add509Cert(..., $isURL = true)` fetches over http/https only and rejects hosts that resolve to loopback/private/link-local/reserved/CGNAT addresses, with redirects disabled (SSRF hardening). `file://` is disabled unless you pass `array('allow_file_scheme' => true)` in `$options`. Only fetch certificates from trusted URLs — a small DNS-rebinding window remains.
* Decrypted XML containing a `DOCTYPE` is rejected to guard against entity-expansion / XXE. Always load untrusted *input* documents yourself with DTD/entity processing disabled.

* Documents carrying a `DOCTYPE` are rejected during signature verification (`locateSignature()` / `verifyDocument()`). This closes the entity-reference bypass in which an `Id="&e;"` attribute is resolved by `getAttribute()` but is invisible to the XPath reference lookup (a libxml2 hashing bug, the same root cause as CVE-2025-23369), causing `verify()` to validate a different node than the one your application reads. Set `$objDSig->forbidDoctype = false` only if you fully trust the document source and require DTD support.

* **Legacy interoperability (temporary):** if you must accept documents/peers that rely on pre-4.0 behaviour, call `$objDSig->enableLegacyMode()` and/or `$objenc->enableLegacyMode()` once after construction. That restores the interoperability settings in one place (DOCTYPE allowed on verify, XPath transforms allowed without count caps, SHA-1 signature and digest algorithms accepted on verify, RSA-1.5 key transport allowed, AES-CBC and TripleDES-CBC data decryption allowed). It does **not** undo always-on hardening such as SignatureMethod/key binding, uniform decryption errors, or DOCTYPE rejection in *decrypted* XML. Prefer migrating peers and removing the call.

## Unreleased compatibility note

This release requires PHP 8.3 or later (4.0 required PHP 8.0 or later) and phpseclib 3.0.58 or later (4.0.2 required 3.0.57 or later).

Signing requires a signature key type (for example, `XMLSecurityKey::RSA_SHA256` or `XMLSecurityKey::ECDSA_SHA256`), not an encryption/key-transport type such as `RSA_1_5` or `RSA_OAEP`. `signData()` and `XMLSecurityDSig::sign()` now throw for this misuse, before emitting a SignatureMethod; `verifySignature()` returns `-1`. This also applies in legacy mode. Encryption/key transport is unchanged.

## Breaking changes (3.1 → 4.0)

### Platform
- **PHP 8.3+ required as of 4.1** (4.0 required 8.0+; was 5.4+ before that)
- **`phpseclib/phpseclib` 3.0.57 or later required as of 4.0.2; 3.0.58 or later as of 4.1**; `ext-openssl` is now optional

### Signature verification
- **DOCTYPE rejected by default** during verification (`locateSignature` / `verifyDocument`). Opt out: `$dsig->forbidDoctype = false` or `enableLegacyMode()`
- **XPath Filtering Transforms rejected by default** on verify. Opt in: `$dsig->allowXPathTransforms = true` or `enableLegacyMode()`. Signing unchanged
- **XPath caps** when enabled: max 5 transforms / 20 namespaces per transform (`$maxXPathTransforms` / `$maxXPathNamespaces`; raised by `enableLegacyMode()`)
- **SHA-2 SignatureMethod/DigestMethod algorithms by default** (since 4.1): `allowedSignatureAlgorithms` / `allowedDigestAlgorithms` default to `XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS` / `DEFAULT_DIGEST_ALGORITHMS` for `verify()`, `validateReference()` and `verifyDocument()`. SHA-1 (rsa-sha1, dsa-sha1, hmac-sha1, sha1 digest): `enableLegacyMode()` or add them to the lists. RIPEMD-160 digests: add to the list. In `verifyDocument()`, a null list falls back to the defaults; add an extra algorithm (for example a SHA-1 digest) explicitly. Low-level methods treat null as no restriction. Signing unchanged
- **`verify()` always requires SignatureMethod === key algorithm**; mismatch throws (not restored by legacy mode)
- **HMAC keys cannot be loaded from certificates or asymmetric keys**
- **References fail closed**: unresolved, external, or duplicate-Id URIs throw; same-document only
- **Unknown CanonicalizationMethod rejected**
- **HMAC verify returns `1`/`0`** — always check `=== 1`

### Encryption / decryption
- **Key transport restricted to RSA-OAEP by default** (`allowedKeyAlgorithms = XMLSecEnc::DEFAULT_KEY_ALGORITHMS`, since 4.1). Widen the list explicitly, or set it to `null` for no key-transport allowlist
- **EncryptedKey must use RSA key transport** (RSA-1.5, RSA-OAEP, RSA-OAEP-MGF1P), even when `allowedKeyAlgorithms` is `null`; AES/3DES keys refuse certificates and PEM/DER key material in `loadKey()`
- **RSA-1.5 key transport denied by default**. Opt in: `$enc->allowRSA15KeyTransport = true` and `$enc->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5`, or `enableLegacyMode()`
- **Data decryption restricted to AES-GCM by default** (`allowedDataAlgorithms = XMLSecEnc::DEFAULT_DATA_ALGORITHMS`, since 4.1). AES-CBC and TripleDES-CBC: `enableLegacyMode()` or add `LEGACY_DATA_ALGORITHMS`. `null` applies no data-encryption allowlist. The same default applies to `staticLocateKeyInfo()` and `XMLSecurityKey::fromEncryptedKeyElement()`. Encryption of a caller-chosen algorithm is unchanged
- **Single decrypt error message**: `Failure decrypting Data` (do not branch on exception text)
- **DOCTYPE rejected in decrypted XML** (not restored by legacy mode)
- **EncryptedKey/RetrievalMethod depth capped**
- **ISO 10126 pad length validated** on CBC decrypt

### Certificate URL fetch (`add509Cert`)
- Only `http`/`https` by default; `file://` needs `['allow_file_scheme' => true]`
- Private/loopback/link-local/reserved/CGNAT targets rejected; redirects disabled

### API signature changes (defaults preserve most callers)
- `processTransforms(..., $signing = false)`
- `staticLocateKeyInfo(..., $depth = 0, $allowRSA15 = false, $allowedKeyAlgorithms = XMLSecEnc::DEFAULT_KEY_ALGORITHMS, $allowedDataAlgorithms = XMLSecEnc::DEFAULT_DATA_ALGORITHMS)`
- `fromEncryptedKeyElement(..., $depth = 0, $allowRSA15 = false, $allowedKeyAlgorithms = XMLSecEnc::DEFAULT_KEY_ALGORITHMS, $allowedDataAlgorithms = XMLSecEnc::DEFAULT_DATA_ALGORITHMS)`

`locateKeyInfo()` passes the instance's `allowRSA15KeyTransport`,
`allowedKeyAlgorithms` and `allowedDataAlgorithms` to every `EncryptedKey` it
resolves (embedded or via `RetrievalMethod`), so the key's `encryptedCtx`
enforces the same policy. Callers of the static methods pass them explicitly;
when omitted, `$allowedKeyAlgorithms` defaults to
`XMLSecEnc::DEFAULT_KEY_ALGORITHMS` and `$allowedDataAlgorithms` defaults to
`XMLSecEnc::DEFAULT_DATA_ALGORITHMS`. Passing `null` for either applies no
allowlist for that list.

### Legacy mode
`$dsig->enableLegacyMode()` / `$enc->enableLegacyMode()` restores **DOCTYPE (verify), XPath transforms + uncapped limits, SHA-1 signature/digest algorithms (verify), RSA-1.5, and CBC data decryption** only (on the signature side it adds rsa-sha1, dsa-sha1, hmac-sha1 and the sha1 digest to `allowedSignatureAlgorithms` / `allowedDigestAlgorithms` when those lists are set; on the encryption side it sets `allowRSA15KeyTransport`, adds RSA-1.5 to `allowedKeyAlgorithms` when that list is set, and adds `LEGACY_DATA_ALGORITHMS` — AES-CBC and TripleDES-CBC — to `allowedDataAlgorithms` when that list is set; a null list is left null, and `verifyDocument()` still falls back to the default signature and digest lists when either of those properties is null; assigning any of these lists afterwards replaces it, so call `enableLegacyMode()` after configuring them). It does **not** undo algorithm/key binding, uniform decrypt errors, decrypted-XML DOCTYPE rejection, Reference fail-closed behavior, SSRF rules, or the PHP/phpseclib requirements.

**Migration tip:** Prefer `verifyDocument()` with a pinned key. Use legacy mode only while updating peers.

### Verifying a signature (recommended)

```php
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->load('./path/to/signed.xml');

// Pin the key/certificate you trust (do NOT read it from the document).
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$objKey->loadKey('./path/to/trusted-cert.pem', true, true);

$objDSig = new XMLSecurityDSig();
// If assertions use custom Id attributes (e.g. WS-Security), declare them first:
// $objDSig->idKeys = array('wsu:Id');
// $objDSig->idNS   = array('wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

try {
    // Throws on any failure; returns the validated nodes on success.
    $validatedNodes = $objDSig->verifyDocument($objKey, $doc);
    // Operate ONLY on $validatedNodes from here on.
} catch (Exception $e) {
    // Verification failed - reject the message.
}
```

### Decrypting XML (recommended recipe)

xmlseclibs does not derive the decryption key from the document: you supply
your own private key, and the document's session key is unwrapped with it. The
recipe below covers the common `EncryptedKey` (key transport) + `EncryptedData`
(data) layout used by SAML and WS-Security, with the algorithm policy pinned.

```php
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->load('./path/to/encrypted.xml');

$objenc = new XMLSecEnc();

// Pin the algorithm policy:
//  - Key transport is restricted to RSA-OAEP by default
//    ($objenc->allowedKeyAlgorithms === XMLSecEnc::DEFAULT_KEY_ALGORITHMS).
//  - RSA-1.5 key transport is denied by default (Bleichenbacher); only
//    enable it if you must interoperate with a legacy peer:
// $objenc->allowRSA15KeyTransport = true;
// $objenc->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5;
//  - Data decryption accepts AES-GCM by default
//    ($objenc->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS).
//    AES-CBC and TripleDES-CBC, either:
// $objenc->enableLegacyMode();
//    or, without also enabling RSA-1.5 key transport:
// $objenc->allowedDataAlgorithms = array_merge(
//     XMLSecEnc::DEFAULT_DATA_ALGORITHMS,
//     XMLSecEnc::LEGACY_DATA_ALGORITHMS
// );

$encData = $objenc->locateEncryptedData($doc);
if (! $encData) {
    throw new Exception('Cannot locate EncryptedData');
}
$objenc->setNode($encData);
$objenc->type = $encData->getAttribute('Type');

// Resolve the session key. locateKey() reads the data algorithm from the
// document; locateKeyInfo() finds the EncryptedKey.
$objKey = $objenc->locateKey();
if (! $objKey) {
    throw new Exception('Unknown data encryption algorithm');
}

if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
    if ($objKeyInfo->isEncrypted) {
        // Load YOUR trusted private key to unwrap the session key.
        $objKeyInfo->loadKey('./path/to/your-private-key.pem', true);
        $sessionKey = $objKeyInfo->encryptedCtx->decryptKey($objKeyInfo);
        $objKey->loadKey($sessionKey);
    }
}

// If the session key was supplied out-of-band (no EncryptedKey), load it here:
// if (empty($objKey->key)) { $objKey->loadKey($sharedSecretBytes); }

// Decrypted content is returned; a DOCTYPE in the plaintext is rejected.
$decrypted = $objenc->decryptNode($objKey, true);
```

If the recipient key is selected by `KeyName` (rather than an embedded
`EncryptedKey`), read `$objKeyInfo->name` and load the matching local private
key yourself before decrypting. Never treat key material from the document as
trusted.

### RSA-OAEP parameters and compatibility

`locateKey()` (including `EncryptedKey` resolution through `locateKeyInfo()`)
reads OAEP parameters only from the selected encrypted element's direct
`EncryptionMethod` child. Following
[XML Encryption 1.1 section 5.5.2](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP):

* Both RSA-OAEP identifiers default to SHA-1 when `ds:DigestMethod` is absent.
* `RSA_OAEP` (`xmlenc11#rsa-oaep`) defaults to MGF1-SHA1 when `xenc11:MGF` is absent.
* `RSA_OAEP_MGF1P` (`rsa-oaep-mgf1p`) always uses MGF1-SHA1 and prohibits an MGF element.
* Digest and MGF hashes are independent. Supported hashes are SHA-1, SHA-224,
  SHA-256, SHA-384 and SHA-512, using their standard XML algorithm URIs.
* `xenc:OAEPparams` is a base64-encoded binary label; omission means an empty label.
  Invalid encodings, unsupported parameters and duplicate parameter elements throw.
* An `xenc:KeySize` is accepted and ignored if it appears at most once and
  holds a positive decimal integer of up to six digits (surrounding whitespace
  allowed). Other forms that the schema permits, such as a leading `+` or
  leading zeros (`+2048`, `02048`), are rejected, as is any other element in
  the `EncryptionMethod`.

Constructing `XMLSecurityKey::RSA_OAEP` yourself still selects
SHA-256/MGF1-SHA256, and constructing `RSA_OAEP_MGF1P` selects SHA-1/MGF1-SHA1.
These constructor defaults apply to **decryption as well as encryption**: they
are used whenever the key is not obtained from the document. A hand-built
`RSA_OAEP` private key passed to `decryptKey()` therefore expects SHA-256 and
cannot unwrap keys from senders that use the XML Encryption defaults
(SHA-1/MGF1-SHA1 with no `DigestMethod`/`MGF`), such as Shibboleth IdP.
For those senders either:

* resolve the key from the document with `locateKeyInfo()` (or
  `XMLSecurityKey::fromEncryptedKeyElement()`), load your private key into the
  returned key, and call `$key->encryptedCtx->decryptKey($key)`. The declared
  or default parameters are then applied; or
* call `setOAEPParameters()` on your hand-built key with the parameters you
  expect (no arguments selects the SHA-1/MGF1-SHA1 defaults).

To configure OAEP explicitly, before encryption or decryption:

```php
$key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP, array('type' => 'public'));
$key->setOAEPParameters(
    XMLSecurityDSig::SHA256,
    'http://www.w3.org/2009/xmlenc11#mgf1sha1',
    'application-label' // Decoded bytes, not base64.
);
```

`setOAEPParameters()` with no arguments selects the specification defaults
(SHA-1/MGF1-SHA1, empty label). `getOAEPParameters()` returns the selected
`digest` and `mgf` URIs and decoded `label`, or `null` for non-OAEP keys.
These settings do not affect RSA-PSS signatures. `encryptKey()` and
`encryptNode()` serialize the parameters actually used, including explicit
SHA-256 declarations and any nonempty label.

**Previously generated ciphertext:** 4.0.0 through 4.0.2 could encrypt with
SHA-256/MGF1-SHA256 under `xmlenc11#rsa-oaep` while omitting the parameters.
That XML declares SHA-1 defaults and is nonconforming; it no longer decrypts
through specification-default key resolution. Regenerate it with explicit
parameters. For a controlled migration of known historical ciphertext only,
an application can explicitly configure the key with the known SHA-256
parameters using trusted out-of-band information. Do not rewrite incoming
signed XML or guess hashes by retrying decryption. There is no automatic
fallback; cryptographic failures retain the uniform `Failure decrypting Data`
message, and algorithm policies and RSA-1.5 restrictions remain in effect.


## How to Install

Install with [`composer.phar`](http://getcomposer.org).

```sh
php composer.phar require "robrichards/xmlseclibs"
```


## Use cases

xmlseclibs is being used in many different software.

* [SimpleSAMLPHP](https://github.com/simplesamlphp/simplesamlphp)
* [LightSAML](https://github.com/lightsaml/lightsaml)
* [OneLogin](https://github.com/onelogin/php-saml)

## Basic usage

The example below shows basic usage of xmlseclibs, with a SHA-256 signature.

```php
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

// Load the XML to be signed
$doc = new DOMDocument();
$doc->load('./path/to/file/tobesigned.xml');

// Create a new Security object 
$objDSig = new XMLSecurityDSig();
// Use the c14n exclusive canonicalization
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
// Sign using SHA-256
$objDSig->addReference(
    $doc, 
    XMLSecurityDSig::SHA256, 
    array('http://www.w3.org/2000/09/xmldsig#enveloped-signature')
);

// Create a new (private) Security key
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));
/*
If key has a passphrase, set it using
$objKey->passphrase = '<passphrase>';
*/
// Load the private key
$objKey->loadKey('./path/to/privatekey.pem', TRUE);

// Sign the XML file
$objDSig->sign($objKey);

// Add the associated public key to the signature
$objDSig->add509Cert(file_get_contents('./path/to/file/mycert.pem'));

// Append the signature to the XML
$objDSig->appendSignature($doc->documentElement);
// Save the signed XML
$doc->save('./path/to/signed.xml');
```

## How to Contribute

* [Open Issues](https://github.com/robrichards/xmlseclibs/issues)
* [Open Pull Requests](https://github.com/robrichards/xmlseclibs/pulls)

Mailing List: https://groups.google.com/forum/#!forum/xmlseclibs
