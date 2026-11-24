--TEST--
EncryptedKey / RetrievalMethod resolution is depth-bounded (DoS protection)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* A RetrievalMethod that points back at its own EncryptedKey forms a cycle. */
$xml = <<<XML
<?xml version="1.0"?>
<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Id="loop">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
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

/* Pin the limit: a chain of MAX_KEYINFO_DEPTH + 1 embedded EncryptedKeys resolves, one more is rejected. */
echo 'MAX_KEYINFO_DEPTH: '.XMLSecEnc::MAX_KEYINFO_DEPTH."\n";
function chain($n) {
    $xml = '';
    for ($i = 0; $i < $n; $i++) {
        $xml = '<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">'
            .'<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>'
            .($xml !== '' ? '<dsig:KeyInfo>'.$xml.'</dsig:KeyInfo>' : '')
            .'<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
    }
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    return $doc->documentElement;
}
foreach (array(XMLSecEnc::MAX_KEYINFO_DEPTH + 1, XMLSecEnc::MAX_KEYINFO_DEPTH + 2) as $n) {
    try {
        XMLSecurityKey::fromEncryptedKeyElement(chain($n));
        echo "chain $n: ok\n";
    } catch (Exception $e) {
        echo "chain $n: ".$e->getMessage()."\n";
    }
}
?>
--EXPECTF--
EncryptedKey reference chain is too deep
MAX_KEYINFO_DEPTH: 10
chain 11: ok
chain 12: EncryptedKey reference chain is too deep
