--TEST--
RetrievalMethod with empty URI does not warn on string offset
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

error_reporting(E_ALL);
$xml = <<<XML
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:KeyInfo>
    <ds:RetrievalMethod URI="" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/>
  </ds:KeyInfo>
</xenc:EncryptedData>
XML;
$doc = new DOMDocument();
$doc->loadXML($xml);
$key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$out = XMLSecEnc::staticLocateKeyInfo($key, $doc->documentElement);
echo ($out === $key ? 'OK' : 'FAIL')."\n";
?>
--EXPECTF--
OK
