--TEST--
XMLSecEnc algorithm policy: RSA-1.5 default-deny + data-algorithm allowlist
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;

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

/* 1. RSA-1.5 key transport is denied by default during key resolution. */
try {
    $objenc = newEnc($xml);
    $objKey = $objenc->locateKey();
    $objenc->locateKeyInfo($objKey);
    print "RSA15_DEFAULT: unexpected success\n";
} catch (Exception $e) {
    print "RSA15_DEFAULT: ".$e->getMessage()."\n";
}

/* 2. RSA-1.5 can be opted into; key resolution then succeeds (no policy block). */
try {
    $objenc = newEnc($xml);
    $objenc->allowRSA15KeyTransport = true;
    $objKey = $objenc->locateKey();
    $objenc->locateKeyInfo($objKey);
    print "RSA15_OPTIN: OK\n";
} catch (Exception $e) {
    print "RSA15_OPTIN: ".$e->getMessage()."\n";
}

/* 3. Data-algorithm allowlist rejects unauthenticated CBC when GCM-only. */
try {
    $objenc = newEnc($xml);
    $objenc->allowedDataAlgorithms = XMLSecEnc::DEFAULT_DATA_ALGORITHMS;
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
