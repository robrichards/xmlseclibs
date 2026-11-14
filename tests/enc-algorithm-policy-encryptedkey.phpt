--TEST--
XMLSecEnc algorithm allowlists apply to EncryptedKey elements resolved through locateKeyInfo()
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function encryptedDocument($transportAlgorithm) {
    $public = new XMLSecurityKey($transportAlgorithm, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $symmetric = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $symmetric->generateSessionKey();
    $enc->encryptKey($public, $symmetric);
    $enc->encryptNode($symmetric);
    return $doc;
}

function decrypt(DOMDocument $doc, $allowedKey, $allowedData = null) {
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = $allowedKey;
    $dec->allowedDataAlgorithms = $allowedData;
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transport = $dec->locateKeyInfo($dataKey);
    if ($transport->encryptedCtx->allowedKeyAlgorithms !== $allowedKey) {
        return 'policy not propagated';
    }
    $transport->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
    $dec->decryptNode($dataKey, true);
    return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
}

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

attempt('allowed transport', function () {
    return decrypt(encryptedDocument(XMLSecurityKey::RSA_OAEP_MGF1P), XMLSecEnc::DEFAULT_KEY_ALGORITHMS, XMLSecEnc::DEFAULT_DATA_ALGORITHMS);
});
attempt('disallowed transport', function () {
    return decrypt(encryptedDocument(XMLSecurityKey::RSA_OAEP_MGF1P), array(XMLSecurityKey::RSA_OAEP));
});
attempt('no allowlist', function () {
    return decrypt(encryptedDocument(XMLSecurityKey::RSA_OAEP), null);
});

/* RetrievalMethod-referenced EncryptedKey elements use the same policy. */
attempt('RetrievalMethod disallowed', function () {
    $doc = new DOMDocument();
    $doc->load(__DIR__ . '/retrievalmethod-findkey.xml');
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = array(XMLSecurityKey::RSA_OAEP);
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->locateKeyInfo($dec->locateKey());
    return 'unexpected success';
});
attempt('RetrievalMethod allowed', function () {
    $doc = new DOMDocument();
    $doc->load(__DIR__ . '/retrievalmethod-findkey.xml');
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = array(XMLSecurityKey::RSA_OAEP_MGF1P);
    $dec->setNode($dec->locateEncryptedData($doc));
    return $dec->locateKeyInfo($dec->locateKey())->getAlgorithm();
});

/* The static entry points accept the allowlists as optional arguments. */
attempt('static disallowed', function () {
    $doc = encryptedDocument(XMLSecurityKey::RSA_OAEP_MGF1P);
    $encKey = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
    XMLSecurityKey::fromEncryptedKeyElement($encKey, 0, false, array(XMLSecurityKey::RSA_OAEP));
    return 'unexpected success';
});
attempt('static default', function () {
    $doc = encryptedDocument(XMLSecurityKey::RSA_OAEP_MGF1P);
    $encKey = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
    return XMLSecurityKey::fromEncryptedKeyElement($encKey)->getAlgorithm();
});
?>
--EXPECTF--
allowed transport: OK
disallowed transport: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
no allowlist: OK
RetrievalMethod disallowed: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
RetrievalMethod allowed: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
static disallowed: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
static default: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
