--TEST--
encryptKey() rejects a symmetric wrapping key before changing the document; RSA-OAEP still round-trips
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function attempt($label, $operation)
{
    try {
        $operation();
        echo "$label: not rejected\n";
    } catch (Exception $e) {
        echo "$label: ".$e->getMessage()."\n";
    }
}

function templateXml($enc)
{
    $property = new ReflectionProperty(XMLSecEnc::class, 'encdoc');
    $doc = $property->getValue($enc);
    $xml = $doc->saveXML();
    return $xml === false ? '' : $xml;
}

$dom = new DOMDocument();
$dom->loadXML('<root>payload</root>');
$before = $dom->saveXML();

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->type = XMLSecEnc::Element;
$templateBefore = templateXml($enc);

$wrapGcm = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$wrapGcm->generateSessionKey();
$wrapCbc = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
$wrapCbc->generateSessionKey();
$session = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$session->generateSessionKey();

attempt('ENCRYPTKEY_GCM', function () use ($enc, $wrapGcm, $session) {
    $enc->encryptKey($wrapGcm, $session);
});
echo 'DOC_GCM: '.($dom->saveXML() === $before ? 'unchanged' : 'changed')."\n";
echo 'TEMPLATE_GCM: '.(templateXml($enc) === $templateBefore ? 'unchanged' : 'changed')."\n";
echo 'ENCKEY_GCM: '.($enc->encKey === null ? 'unset' : 'set')."\n";

attempt('ENCRYPTKEY_CBC', function () use ($enc, $wrapCbc, $session) {
    $enc->encryptKey($wrapCbc, $session, false);
});
echo 'DOC_CBC: '.($dom->saveXML() === $before ? 'unchanged' : 'changed')."\n";
echo 'TEMPLATE_CBC: '.(templateXml($enc) === $templateBefore ? 'unchanged' : 'changed')."\n";
echo 'ENCKEY_CBC: '.($enc->encKey === null ? 'unset' : 'set')."\n";

$public = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP, array('type' => 'public'));
$public->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
$enc->encryptKey($public, $session);
$enc->encryptNode($session);
echo 'ENCRYPTEDKEY_COUNT: '.$dom->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->length."\n";

$dec = new XMLSecEnc();
$dec->setNode($dec->locateEncryptedData($dom));
$dec->type = XMLSecEnc::Element;
$dataKey = $dec->locateKey();
$transportKey = $dec->locateKeyInfo($dataKey);
$transportKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$dataKey->loadKey($transportKey->encryptedCtx->decryptKey($transportKey));
$dec->decryptNode($dataKey, true);
echo 'ROUNDTRIP: '.($dom->documentElement->textContent === 'payload' ? 'OK' : 'FAIL')."\n";
?>
--EXPECTF--
ENCRYPTKEY_GCM: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
DOC_GCM: unchanged
TEMPLATE_GCM: unchanged
ENCKEY_GCM: unset
ENCRYPTKEY_CBC: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
DOC_CBC: unchanged
TEMPLATE_CBC: unchanged
ENCKEY_CBC: unset
ENCRYPTEDKEY_COUNT: 1
ROUNDTRIP: OK
