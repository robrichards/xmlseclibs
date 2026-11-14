--TEST--
Signature-capable keys still sign and verify; RSA key transport is unchanged
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;

foreach ([
    XMLSecurityKey::RSA_SHA1, XMLSecurityKey::RSA_SHA256,
    XMLSecurityKey::RSA_SHA384, XMLSecurityKey::RSA_SHA512,
    XMLSecurityKey::RSA_SHA256_MGF1, XMLSecurityKey::HMAC_SHA1,
    XMLSecurityKey::ECDSA_SHA256, XMLSecurityKey::ECDSA_SHA384,
    XMLSecurityKey::ECDSA_SHA512,
] as $type) {
    $private = new XMLSecurityKey($type, ['type' => 'private']);
    $public = new XMLSecurityKey($type, ['type' => 'public']);
    if ($type === XMLSecurityKey::HMAC_SHA1) {
        $private->loadKey('signature-test-shared-secret');
        $public->loadKey('signature-test-shared-secret');
    } elseif (in_array($type, [
        XMLSecurityKey::ECDSA_SHA256,
        XMLSecurityKey::ECDSA_SHA384,
        XMLSecurityKey::ECDSA_SHA512,
    ], true)) {
        $curve = [
            XMLSecurityKey::ECDSA_SHA256 => 'p256',
            XMLSecurityKey::ECDSA_SHA384 => 'p384',
            XMLSecurityKey::ECDSA_SHA512 => 'p521',
        ][$type];
        $private->loadKey(__DIR__ . "/ec-$curve-key.pem", true);
        $public->loadKey(__DIR__ . "/ec-$curve-cert.pem", true, true);
    } else {
        $private->loadKey(__DIR__ . '/privkey.pem', true);
        $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    }
    $signature = $private->signData('payload');
    $ok = $public->verifySignature('payload', $signature) === 1
        && $public->verifySignature('tampered', $signature) === 0;
    if ($type === XMLSecurityKey::RSA_SHA256 && function_exists('openssl_verify')) {
        $ok = $ok && openssl_verify('payload', $signature, $public->key, OPENSSL_ALGO_SHA256) === 1;
    } elseif ($type === XMLSecurityKey::HMAC_SHA1) {
        $ok = $ok && hash_equals(hash_hmac('sha1', 'payload', 'signature-test-shared-secret', true), $signature);
    }
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->sign($private);
    $dsig->canonicalizeSignedInfo();
    echo ($ok && $dsig->verify($public) === 1 ? 'SIGNATURE OK' : 'FAIL') . "\n";
}

foreach ([XMLSecurityKey::RSA_1_5, XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_OAEP] as $type) {
    $public = new XMLSecurityKey($type, ['type' => 'public']);
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $private = new XMLSecurityKey($type, ['type' => 'private']);
    $private->loadKey(__DIR__ . '/privkey.pem', true);
    $session = str_repeat('s', 32);
    $ok = $private->decryptData($public->encryptData($session)) === $session;

    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->allowRSA15KeyTransport = true;
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $symmetric = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $symmetric->loadKey($session);
    $enc->encryptKey($public, $symmetric);
    $enc->encryptNode($symmetric);

    $decrypt = new XMLSecEnc();
    $decrypt->allowRSA15KeyTransport = true;
    $encrypted = $decrypt->locateEncryptedData($doc);
    $decrypt->setNode($encrypted);
    $decrypt->type = XMLSecEnc::Element;
    $dataKey = $decrypt->locateKey();
    $transportKey = $decrypt->locateKeyInfo($dataKey);
    $transportKey->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transportKey->encryptedCtx->decryptKey($transportKey));
    $decrypt->decryptNode($dataKey, true);
    echo ($ok && $doc->documentElement->tagName === 'root'
        && $doc->documentElement->textContent === 'payload' ? 'TRANSPORT OK' : 'FAIL') . "\n";
}
?>
--EXPECTF--
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
SIGNATURE OK
TRANSPORT OK
TRANSPORT OK
TRANSPORT OK
