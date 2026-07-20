--TEST--
EncryptedKey / RetrievalMethod resolution is depth-bounded (DoS protection)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* A RetrievalMethod that points back at its own EncryptedKey forms a cycle. */
$xml = <<<XML
<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Id="loop">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
  <dsig:KeyInfo>
    <dsig:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#loop"/>
  </dsig:KeyInfo>
  <xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedKey>
XML;

$doc = new DOMDocument();
$doc->loadXML($xml);

try {
    XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
    echo "no exception\n";
} catch (Exception $e) {
    echo $e->getMessage()."\n";
}
?>
--EXPECTF--
EncryptedKey reference chain is too deep
