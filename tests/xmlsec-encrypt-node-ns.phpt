--TEST--
Basic Encryption: Content
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

$dom = new DOMDocument();
$dom->load(dirname(__FILE__) . '/basic-doc-withns.xml');

$objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey->generateSessionKey();

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->encryptKey($siteKey, $objKey);

$enc->type = XMLSecEnc::Content;
$encNode = $enc->encryptNode($objKey);

$root = $dom->documentElement->firstChild;
echo $root->localName."\n";

?>
--EXPECTF--
EncryptedData
