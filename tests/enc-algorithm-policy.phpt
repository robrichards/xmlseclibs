--TEST--
XMLSecEnc algorithm policy: RSA-1.5 default-deny + data-algorithm allowlist
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$xml = <<<XML
<?xml version="1.0"?>
<Root xmlns="urn:envelope">
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Content">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
  <dsig:KeyInfo>
    <xenc:EncryptedKey>
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
      <xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedKey>
  </dsig:KeyInfo>
  <xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedData>
</Root>
XML;

function newEnc($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $objenc = new XMLSecEnc();
    $encData = $objenc->locateEncryptedData($doc);
    $objenc->setNode($encData);
    $objenc->type = $encData->getAttribute("Type");
    return $objenc;
}

/* The fixture's data algorithm is AES-CBC, outside the default data list. */
function allowLegacyData($objenc) {
    foreach (XMLSecEnc::LEGACY_DATA_ALGORITHMS as $algorithm) {
        $objenc->allowedDataAlgorithms[] = $algorithm;
    }
}

/* 1. RSA-1.5 key transport is denied by default during key resolution. */
try {
    $objenc = newEnc($xml);
    allowLegacyData($objenc);
    $objKey = $objenc->locateKey();
    $objenc->locateKeyInfo($objKey);
    print "RSA15_DEFAULT: unexpected success\n";
} catch (Exception $e) {
    print "RSA15_DEFAULT: ".$e->getMessage()."\n";
}

/* 2. RSA-1.5 can be opted into (flag + key-transport allowlist); key
 *    resolution then succeeds (no policy block). */
try {
    $objenc = newEnc($xml);
    allowLegacyData($objenc);
    $objenc->allowRSA15KeyTransport = true;
    $objenc->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5;
    $objKey = $objenc->locateKey();
    $objenc->locateKeyInfo($objKey);
    print "RSA15_OPTIN: OK\n";
} catch (Exception $e) {
    print "RSA15_OPTIN: ".$e->getMessage()."\n";
}

/* 3. The default data-algorithm list rejects AES-CBC. */
try {
    $objenc = newEnc($xml);
    $objenc->locateKey();
    print "DATA_ALLOWLIST: unexpected success\n";
} catch (Exception $e) {
    print "DATA_ALLOWLIST: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
RSA15_DEFAULT: RSA-1.5 key transport is disabled (Bleichenbacher risk); set allowRSA15KeyTransport = true to opt in
RSA15_OPTIN: OK
DATA_ALLOWLIST: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
