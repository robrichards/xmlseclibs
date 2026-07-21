#xmlseclibs 

xmlseclibs is a library written in PHP for working with XML Encryption and Signatures.

The author of xmlseclibs is Rob Richards.

# Branches
Master is currently the only actively maintained branch.
* master: requires PHP version 8.0+
* 3.1: Added AES-GCM support requiring 7.1+
* 3.0: Removes mcrypt usage requiring 5.4+ (5.6.24+ recommended for security reasons)
* 2.0: Contains namespace support requiring 5.3+
* 1.4: Contains auto-loader support while also maintaining backwards compatiblity with the older 1.3 version using the xmlseclibs.php file. Supports PHP 5.2+

# Requirements

xmlseclibs requires PHP version 8.0 or greater. OpenSSL is optional (phpseclib is used for crypto).

## Security notes

* Prefer the safe-by-default verifier `verifyDocument()` (see below). It requires a caller-supplied (pinned) key, never derives the key from the document's `KeyInfo`, enforces an algorithm allowlist for both the `SignatureMethod` and every `DigestMethod`, and only reports success when every reference validated. It returns the validated nodes for you to operate on.
* If you use the low-level primitives directly, always check verification with a strict comparison: `$objDSig->verify($key) === 1`. A return of `-1` is an error and is truthy in boolean context.
* After `validateReference()`, use `getValidatedNodes()` and operate only on those nodes (especially for SAML / WS-Security). Do not re-select assertions by Id from the whole document.
* Do not trust a signing certificate from `KeyInfo` alone. Load and pin trusted keys yourself.
* By default `verifyDocument()` accepts only SHA-256/384/512 digests and RSA-SHA-256/384/512 (and RSA-PSS) signatures. To interoperate with legacy peers, widen the sets explicitly, e.g. `$objDSig->allowedSignatureAlgorithms[] = XMLSecurityKey::RSA_SHA1;`.
* Prefer RSA-OAEP and AES-GCM for encryption. RSA-1.5 and CBC algorithms remain for legacy interoperability only.
* XPath transforms are capped by default (`maxXPathTransforms` / `maxXPathNamespaces`, defaults 5 and 20). Raise or lower these on the `XMLSecurityDSig` instance if your use case needs different limits.

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
