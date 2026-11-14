--TEST--
locateKey() reads only the direct EncryptionMethod; encryptNode() with RSA-OAEP keys round-trips
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function algorithmOf($key) {
    return $key === null ? 'null' : $key->getAlgorithm();
}

$ns = 'xmlns:e="'.XMLSecEnc::XMLENCNS.'" xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS.'"';
$doc = new DOMDocument();
$doc->loadXML('<Wrap '.$ns.'><e:EncryptedData Type="'.XMLSecEnc::Element.'">'
    .'<e:EncryptionMethod Algorithm="'.XMLSecurityKey::AES128_GCM.'"/>'
    .'<e:CipherData><e:CipherValue>AA==</e:CipherValue></e:CipherData></e:EncryptedData></Wrap>');
$encData = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);

$enc = new XMLSecEnc();
echo 'EncryptedData: '.algorithmOf($enc->locateKey($encData))."\n";
echo 'ancestor argument: '.algorithmOf($enc->locateKey($doc->documentElement))."\n";
$enc = new XMLSecEnc();
$enc->setNode($doc->documentElement);
echo 'ancestor node: '.algorithmOf($enc->locateKey())."\n";

/* EncryptionMethod is optional on EncryptedData; the nested EncryptedKey's must not be used. */
$doc = new DOMDocument();
$doc->loadXML('<e:EncryptedData '.$ns.' Type="'.XMLSecEnc::Element.'"><ds:KeyInfo><e:EncryptedKey>'
    .'<e:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP_MGF1P.'"/>'
    .'<e:CipherData><e:CipherValue>AA==</e:CipherValue></e:CipherData></e:EncryptedKey></ds:KeyInfo>'
    .'<e:CipherData><e:CipherValue>AA==</e:CipherValue></e:CipherData></e:EncryptedData>');
$enc = new XMLSecEnc();
echo 'no own EncryptionMethod: '.algorithmOf($enc->locateKey($doc->documentElement))."\n";

/* encryptNode() with an RSA-OAEP key serializes the parameters it used. */
$configurations = array(
    'RSA_OAEP default' => array(XMLSecurityKey::RSA_OAEP, null),
    'RSA_OAEP SHA1' => array(XMLSecurityKey::RSA_OAEP, array(XMLSecurityDSig::SHA1, XMLSecEnc::XMLENC11NS.'mgf1sha1', '')),
    'RSA_OAEP label' => array(XMLSecurityKey::RSA_OAEP, array(XMLSecurityDSig::SHA256, XMLSecEnc::XMLENC11NS.'mgf1sha1', "\x00lbl")),
    'RSA_OAEP_MGF1P default' => array(XMLSecurityKey::RSA_OAEP_MGF1P, null),
);
foreach ($configurations as $name => list($algorithm, $parameters)) {
    $public = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    if ($parameters !== null) {
        $public->setOAEPParameters($parameters[0], $parameters[1], $parameters[2]);
    }
    $doc = new DOMDocument();
    $doc->loadXML('<root><secret>payload</secret></root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement->firstChild);
    $enc->type = XMLSecEnc::Element;
    $enc->encryptNode($public);

    $method = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptionMethod')->item(0);
    $declared = array();
    foreach ($method->childNodes as $child) {
        if ($child instanceof DOMElement) {
            $value = $child->localName === 'OAEPparams'
                ? (base64_decode($child->textContent) === "\x00lbl" ? 'label' : 'wrong label')
                : $child->getAttribute('Algorithm');
            $declared[] = $child->localName.'='.$value;
        }
    }

    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = XMLSecEnc::DEFAULT_KEY_ALGORITHMS;
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $private = $dec->locateKey();
    $private->loadKey(__DIR__ . '/privkey.pem', true);
    $dec->decryptNode($private, true);
    $ok = $doc->documentElement->firstChild->nodeName === 'secret'
        && $doc->documentElement->textContent === 'payload'
        && $private->getOAEPParameters() == $public->getOAEPParameters();
    echo "$name: ".($ok ? 'OK' : 'FAIL').' ['.implode(', ', $declared)."]\n";
}
?>
--EXPECTF--
EncryptedData: http://www.w3.org/2009/xmlenc11#aes128-gcm
ancestor argument: null
ancestor node: null
no own EncryptionMethod: null
RSA_OAEP default: OK [DigestMethod=http://www.w3.org/2001/04/xmlenc#sha256, MGF=http://www.w3.org/2009/xmlenc11#mgf1sha256]
RSA_OAEP SHA1: OK [DigestMethod=http://www.w3.org/2000/09/xmldsig#sha1, MGF=http://www.w3.org/2009/xmlenc11#mgf1sha1]
RSA_OAEP label: OK [OAEPparams=label, DigestMethod=http://www.w3.org/2001/04/xmlenc#sha256, MGF=http://www.w3.org/2009/xmlenc11#mgf1sha1]
RSA_OAEP_MGF1P default: OK [DigestMethod=http://www.w3.org/2000/09/xmldsig#sha1]
