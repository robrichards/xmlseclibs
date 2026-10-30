--TEST--
ECDSA algorithms are bound to EC keys on prime curves, and RSA algorithms to RSA keys
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

$data = 'data to sign';

function signWith($algorithm, $keyFile) {
    global $data;
    $objKey = new XMLSecurityKey($algorithm, array('type' => 'private'));
    $objKey->loadKey(dirname(__FILE__) . '/' . $keyFile, true);
    try {
        $objKey->signData($data);
        return 'signed';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

function verifyWith($algorithm, $certFile, $signature) {
    global $data;
    $objKey = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/' . $certFile, true, true);
    return $objKey->verifySignature($data, $signature);
}

/* Signing */
print "ECDSA with RSA key: " . signWith(XMLSecurityKey::ECDSA_SHA256, 'privkey.pem') . "\n";
print "RSA with EC key: " . signWith(XMLSecurityKey::RSA_SHA256, 'ec-p256-key.pem') . "\n";
print "ECDSA with Ed25519 key: " . signWith(XMLSecurityKey::ECDSA_SHA256, 'ed25519-key.pem') . "\n";

/* Verification returns -1 (error) when the key type does not match. */
$objKey = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'private'));
$objKey->loadKey(dirname(__FILE__) . '/ec-p256-key.pem', true);
$ecSignature = $objKey->signData($data);

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$rsaSignature = $objKey->signData($data);

print "ECDSA verify with EC cert: " . verifyWith(XMLSecurityKey::ECDSA_SHA256, 'ec-p256-cert.pem', $ecSignature) . "\n";
print "ECDSA verify with RSA cert: " . verifyWith(XMLSecurityKey::ECDSA_SHA256, 'mycert.pem', $rsaSignature) . "\n";
print "RSA verify with EC cert: " . verifyWith(XMLSecurityKey::RSA_SHA256, 'ec-p256-cert.pem', $ecSignature) . "\n";
print "ECDSA verify with other digest: " . verifyWith(XMLSecurityKey::ECDSA_SHA512, 'ec-p256-cert.pem', $ecSignature) . "\n";
?>
--EXPECTF--
ECDSA with RSA key: Expected an EC key
RSA with EC key: Expected an RSA key
ECDSA with Ed25519 key: ECDSA requires a key on a named prime curve
ECDSA verify with EC cert: 1
ECDSA verify with RSA cert: -1
RSA verify with EC cert: -1
ECDSA verify with other digest: 0
