--TEST--
Basic Encryption
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

if (file_exists(dirname(__FILE__) . '/oaep_sha1.xml')) {
    unlink(dirname(__FILE__) . '/oaep_sha1.xml');
}

$dom = new DOMDocument();
$dom->load(dirname(__FILE__) . '/basic-doc.xml');

$objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey->generateSessionKey();

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->encryptKey($siteKey, $objKey);

$enc->type = XMLSecEnc::Element;
$encNode = $enc->encryptNode($objKey);

$dom->save(dirname(__FILE__) . '/oaep_sha1.xml');

$xPath = new DOMXPath($dom);
$xPath->registerNamespace('dsig', 'http://www.w3.org/2000/09/xmldsig#');
$xPath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

$queriedNode = $xPath->query(
    '/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate'
);
if ($queriedNode->length !== 0) {
    echo 'X509Certificate was not expected to be found in KeyInfo';
}

$root = $dom->documentElement;
echo $root->localName."\n";

unlink(dirname(__FILE__) . '/oaep_sha1.xml');

?>
--EXPECTF--
EncryptedData
