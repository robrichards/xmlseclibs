--TEST--
Encryption without modifying original data
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

$dom = new DOMDocument();
$dom->load(dirname(__FILE__) . '/basic-doc.xml');

$origData = $dom->saveXML();

$objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey->generateSessionKey();

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->encryptKey($siteKey, $objKey);

$enc->type = XMLSecEnc::ELEMENT;
$encNode = $enc->encryptNode($objKey, false);

$newData = $dom->saveXML();
if ($newData !== $origData) {
    echo "Original data was modified.\n";
}

if ($encNode->namespaceURI !== XMLSecEnc::XMLENCNS || $encNode->localName !== 'EncryptedData') {
    echo "Encrypted node wasn't a <xenc:EncryptedData>-element.\n";
}

?>
--EXPECTF--
