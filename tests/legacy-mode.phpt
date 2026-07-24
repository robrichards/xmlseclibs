--TEST--
enableLegacyMode() restores pre-4.0 interoperability defaults
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

/* --- Signature side --- */
$dsig = new XMLSecurityDSig();
print "DSIG_DEFAULT: forbidDoctype=".($dsig->forbidDoctype ? '1' : '0')
    ." allowXPath=".($dsig->allowXPathTransforms ? '1' : '0')
    ." maxXF=".$dsig->maxXPathTransforms
    ." maxXN=".$dsig->maxXPathNamespaces."\n";

$dsig->enableLegacyMode();
print "DSIG_LEGACY: forbidDoctype=".($dsig->forbidDoctype ? '1' : '0')
    ." allowXPath=".($dsig->allowXPathTransforms ? '1' : '0')
    ." maxXF=".($dsig->maxXPathTransforms === PHP_INT_MAX ? 'MAX' : $dsig->maxXPathTransforms)
    ." maxXN=".($dsig->maxXPathNamespaces === PHP_INT_MAX ? 'MAX' : $dsig->maxXPathNamespaces)."\n";

/* DOCTYPE is accepted after enableLegacyMode(). */
$signed = file_get_contents(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
$withDoctype = preg_replace(
    '/(<\?xml[^>]*\?>\n)/',
    "$1<!DOCTYPE Root [ <!ENTITY e \"anything\"> ]>\n",
    $signed,
    1
);
$doc = new DOMDocument();
$doc->loadXML($withDoctype, LIBXML_NOENT);
$dsig = new XMLSecurityDSig();
$dsig->enableLegacyMode();
try {
    $dsig->locateSignature($doc);
    print "DSIG_DOCTYPE: accepted\n";
} catch (Exception $e) {
    print "DSIG_DOCTYPE: ".$e->getMessage()."\n";
}

/* --- Encryption side --- */
$enc = new XMLSecEnc();
print "ENC_DEFAULT: allowRSA15=".($enc->allowRSA15KeyTransport ? '1' : '0')."\n";
$enc->enableLegacyMode();
print "ENC_LEGACY: allowRSA15=".($enc->allowRSA15KeyTransport ? '1' : '0')."\n";

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
$doc = new DOMDocument();
$doc->loadXML($xml);
$objenc = new XMLSecEnc();
$objenc->enableLegacyMode();
$encData = $objenc->locateEncryptedData($doc);
$objenc->setNode($encData);
$objenc->type = $encData->getAttribute("Type");
try {
    $objKey = $objenc->locateKey();
    $objenc->locateKeyInfo($objKey);
    print "ENC_RSA15: accepted\n";
} catch (Exception $e) {
    print "ENC_RSA15: ".$e->getMessage()."\n";
}

/* enableLegacyMode() returns $this for chaining. */
$chained = (new XMLSecurityDSig())->enableLegacyMode();
print "CHAIN: ".(($chained instanceof XMLSecurityDSig && $chained->allowXPathTransforms) ? 'ok' : 'fail')."\n";
?>
--EXPECTF--
DSIG_DEFAULT: forbidDoctype=1 allowXPath=0 maxXF=5 maxXN=20
DSIG_LEGACY: forbidDoctype=0 allowXPath=1 maxXF=MAX maxXN=MAX
DSIG_DOCTYPE: accepted
ENC_DEFAULT: allowRSA15=0
ENC_LEGACY: allowRSA15=1
ENC_RSA15: accepted
CHAIN: ok
