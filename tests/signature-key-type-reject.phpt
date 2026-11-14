--TEST--
Encryption-only keys cannot sign or verify signatures, or emit a SignatureMethod
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

function rejected(callable $fn, XMLSecurityKey $key) {
    try {
        $fn();
        return false;
    } catch (Exception $e) {
        return strpos($e->getMessage(), "Key type '" . $key->type . "' cannot be used for signatures;") === 0
            && strpos($e->getMessage(), 'XMLSecurityKey::RSA_SHA256') !== false;
    }
}

$rsaTypes = [XMLSecurityKey::RSA_1_5, XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_OAEP];
$types = array_merge($rsaTypes, [
    XMLSecurityKey::TRIPLEDES_CBC,
    XMLSecurityKey::AES128_CBC, XMLSecurityKey::AES192_CBC, XMLSecurityKey::AES256_CBC,
    XMLSecurityKey::AES128_GCM, XMLSecurityKey::AES192_GCM, XMLSecurityKey::AES256_GCM,
]);
foreach ($types as $type) {
    $private = new XMLSecurityKey($type, ['type' => 'private']);
    $public = new XMLSecurityKey($type, ['type' => 'public']);
    if (in_array($type, $rsaTypes, true)) {
        $private->loadKey(__DIR__ . '/privkey.pem', true);
        $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    } else {
        $public->loadKey($private->generateSessionKey());
    }
    $signRejected = rejected(function () use ($private) {
        $private->signData('payload');
    }, $private);
    $verifyRejected = $public->verifySignature('payload', 'signature') === -1;
    $dsig = new XMLSecurityDSig();
    $dsig->enableLegacyMode(); // Legacy interoperability must not undo this check.
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $doc = new DOMDocument();
    $doc->loadXML('<root/>');
    $before = $doc->saveXML();
    $sigBefore = $dsig->sigNode->ownerDocument->saveXML();
    $xmlRejected = rejected(function () use ($dsig, $private, $doc) {
        $dsig->sign($private, $doc->documentElement);
    }, $private);
    $unchanged = $before === $doc->saveXML()
        && $sigBefore === $dsig->sigNode->ownerDocument->saveXML();
    echo ($signRejected && $verifyRejected && $xmlRejected && $unchanged ? 'OK' : 'FAIL') . "\n";
}

// Changing the public type must not disguise an encryption-key configuration.
$key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
$key->loadKey(__DIR__ . '/privkey.pem', true);
$key->type = XMLSecurityKey::RSA_SHA256;
echo (rejected(function () use ($key) { $key->signData('payload'); }, $key) ? 'OK' : 'FAIL') . "\n";
echo ($key->verifySignature('payload', 'signature') === -1 ? 'OK' : 'FAIL') . "\n";
?>
--EXPECTF--
OK
OK
OK
OK
OK
OK
OK
OK
OK
OK
OK
OK
