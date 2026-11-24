--TEST--
EncryptedKey must use an asymmetric key transport algorithm; symmetric keys reject asymmetric material
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\PublicKeyLoader;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const NS = 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

function encryptedKey($algorithm, $attrs = '', $keyInfo = '') {
    return '<xenc:EncryptedKey'.$attrs.'><xenc:EncryptionMethod Algorithm="'.$algorithm.'"/>'
        .($keyInfo !== '' ? '<ds:KeyInfo>'.$keyInfo.'</ds:KeyInfo>' : '')
        .'<xenc:CipherData><xenc:CipherValue>QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedKey>';
}

function encryptedData($keyInfo, $after = '') {
    return '<Root '.NS.'><xenc:EncryptedData Type="'.XMLSecEnc::Element.'">'
        .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
        .'<ds:KeyInfo>'.$keyInfo.'</ds:KeyInfo>'
        .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedData>'.$after.'</Root>';
}

/* Resolve the EncryptedKey through locateKeyInfo() with the given policy. */
function resolve($xml, $keyAlgs, $dataAlgs = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = $keyAlgs;
    $dec->allowedDataAlgorithms = $dataAlgs;
    $dec->setNode($dec->locateEncryptedData($doc));
    return $dec->locateKeyInfo($dec->locateKey())->getAlgorithm();
}

$symmetric = array(
    'AES128_CBC' => XMLSecurityKey::AES128_CBC,
    'AES256_GCM' => XMLSecurityKey::AES256_GCM,
    'TRIPLEDES_CBC' => XMLSecurityKey::TRIPLEDES_CBC,
);

/* 1. Rejected under the default lists, under null lists, and when the data list names the algorithm. */
foreach ($symmetric as $label => $alg) {
    $xml = encryptedData(encryptedKey($alg));
    attempt("$label DEFAULT", function () use ($xml) {
        return resolve($xml, XMLSecEnc::DEFAULT_KEY_ALGORITHMS);
    });
    attempt("$label NULL", function () use ($xml) {
        return resolve($xml, null, null);
    });
    attempt("$label DATA_LIST", function () use ($xml, $alg) {
        return resolve($xml, null, array_unique(array(XMLSecurityKey::AES256_GCM, $alg)));
    });
}

/* 2. Nested and RetrievalMethod-referenced EncryptedKeys. */
$nested = encryptedData(encryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, '', encryptedKey(XMLSecurityKey::AES256_GCM)));
attempt('NESTED NULL', function () use ($nested) {
    return resolve($nested, null);
});
$retrieval = encryptedData(
    '<ds:RetrievalMethod URI="#ek1" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/>',
    str_replace('<xenc:EncryptedKey>', '<xenc:EncryptedKey '.NS.'>', encryptedKey(XMLSecurityKey::AES256_GCM, ' Id="ek1"'))
);
attempt('RETRIEVAL NULL', function () use ($retrieval) {
    return resolve($retrieval, null);
});

/* 3. Static helpers, with every allowlist disabled. */
$doc = new DOMDocument();
$doc->loadXML($nested);
$outer = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
$inner = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(1);
attempt('STATIC_FROM NULL', function () use ($inner) {
    return XMLSecurityKey::fromEncryptedKeyElement($inner, 0, true, null, null)->getAlgorithm();
});
attempt('STATIC_LOCATE NULL', function () use ($outer) {
    $base = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
    return XMLSecEnc::staticLocateKeyInfo($base, $outer, 0, true, null, null)->getAlgorithm();
});

/* 4. Caller-built EncryptedKey context: decryptKey()/decryptNode() check the key's algorithm first. */
function symmetricEncryptedKey() {
    $key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $key->loadKey(str_repeat("\x01", 32));
    $key->isEncrypted = true;
    return $key;
}
attempt('DECRYPTKEY ENCRYPTEDKEY_NODE', function () use ($inner) {
    $ctx = new XMLSecEnc();
    $ctx->allowedKeyAlgorithms = null;
    $ctx->setNode($inner);
    return bin2hex($ctx->decryptKey(symmetricEncryptedKey()));
});
attempt('DECRYPTNODE ENCRYPTEDKEY_NODE', function () use ($inner) {
    $ctx = new XMLSecEnc();
    $ctx->allowedKeyAlgorithms = null;
    $ctx->setNode($inner);
    return bin2hex($ctx->decryptNode(symmetricEncryptedKey(), false));
});
attempt('DECRYPTKEY OTHER_NODE', function () {
    $d = new DOMDocument();
    $d->loadXML(encryptedData(''));
    $ctx = new XMLSecEnc();
    $ctx->allowedKeyAlgorithms = null;
    $ctx->setNode($ctx->locateEncryptedData($d));
    return bin2hex($ctx->decryptKey(symmetricEncryptedKey()));
});

/* 5. Normal RSA-OAEP flows are unchanged (default list and null). */
function roundtrip($transport, $keyAlgs) {
    $public = new XMLSecurityKey($transport, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $session = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $session->generateSessionKey();
    $enc->encryptKey($public, $session);
    $enc->encryptNode($session);

    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = $keyAlgs;
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transportKey = $dec->locateKeyInfo($dataKey);
    $transportKey->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transportKey->encryptedCtx->decryptKey($transportKey));
    $dec->decryptNode($dataKey, true);
    return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
}
foreach (array('OAEP' => XMLSecurityKey::RSA_OAEP, 'OAEP_MGF1P' => XMLSecurityKey::RSA_OAEP_MGF1P) as $label => $alg) {
    attempt("ROUNDTRIP $label DEFAULT", function () use ($alg) {
        return roundtrip($alg, XMLSecEnc::DEFAULT_KEY_ALGORITHMS);
    });
    attempt("ROUNDTRIP $label NULL", function () use ($alg) {
        return roundtrip($alg, null);
    });
}

/* 6. Symmetric key types refuse certificates and asymmetric key material; raw keys still load. */
$der = PublicKeyLoader::load(file_get_contents(__DIR__ . '/privkey.pem'))->toString('PKCS8', array('binary' => true));
$cases = array(
    'PEM_PRIVATE_FILE' => array(XMLSecurityKey::AES256_GCM, __DIR__ . '/privkey.pem', true, false),
    'PEM_CERT' => array(XMLSecurityKey::AES128_CBC, file_get_contents(__DIR__ . '/mycert.pem'), false, false),
    'CERT_FLAG' => array(XMLSecurityKey::AES256_CBC, __DIR__ . '/mycert.pem', true, true),
    'DER_PRIVATE' => array(XMLSecurityKey::TRIPLEDES_CBC, $der, false, false),
    'RAW_EXACT' => array(XMLSecurityKey::AES256_GCM, random_bytes(32), false, false),
    'RAW_OVERLONG' => array(XMLSecurityKey::AES128_GCM, str_repeat("\x42", 48), false, false),
);
foreach ($cases as $label => [$alg, $material, $isFile, $isCert]) {
    attempt("LOADKEY $label", function () use ($alg, $material, $isFile, $isCert) {
        $key = new XMLSecurityKey($alg);
        $key->loadKey($material, $isFile, $isCert);
        return 'loaded';
    });
}
attempt('LOADKEY GENERATED', function () {
    for ($i = 0; $i < 200; $i++) {
        $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $key->loadKey($key->generateSessionKey());
    }
    return 'loaded';
});
attempt('LOADKEY HMAC', function () {
    $key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
    $key->loadKey('shared-secret');
    return 'loaded';
});
?>
--EXPECTF--
AES128_CBC DEFAULT: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
AES128_CBC NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
AES128_CBC DATA_LIST: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
AES256_GCM DEFAULT: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
AES256_GCM NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
AES256_GCM DATA_LIST: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
TRIPLEDES_CBC DEFAULT: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
TRIPLEDES_CBC NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
TRIPLEDES_CBC DATA_LIST: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
NESTED NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
RETRIEVAL NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
STATIC_FROM NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
STATIC_LOCATE NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
DECRYPTKEY ENCRYPTEDKEY_NODE: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
DECRYPTNODE ENCRYPTEDKEY_NODE: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
DECRYPTKEY OTHER_NODE: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
ROUNDTRIP OAEP DEFAULT: OK
ROUNDTRIP OAEP NULL: OK
ROUNDTRIP OAEP_MGF1P DEFAULT: OK
ROUNDTRIP OAEP_MGF1P NULL: OK
LOADKEY PEM_PRIVATE_FILE: Asymmetric key material cannot be used as a symmetric key
LOADKEY PEM_CERT: Asymmetric key material cannot be used as a symmetric key
LOADKEY CERT_FLAG: An X.509 certificate cannot be used as a symmetric key
LOADKEY DER_PRIVATE: Asymmetric key material cannot be used as a symmetric key
LOADKEY RAW_EXACT: loaded
LOADKEY RAW_OVERLONG: loaded
LOADKEY GENERATED: loaded
LOADKEY HMAC: loaded
