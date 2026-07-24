--TEST--
HMAC key must not be created from asymmetric public material (key confusion)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

$pubCert = file_get_contents(dirname(__FILE__) . '/mycert.pem');

/* 1) Loading a certificate string into an HMAC key must be rejected. */
try {
    $key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
    $key->loadKey($pubCert);
    echo "LOAD_PEM: not rejected\n";
} catch (Exception $e) {
    echo "LOAD_PEM: ".$e->getMessage()."\n";
}

/* 2) Loading with the isCert flag into an HMAC key must be rejected. */
try {
    $key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
    $key->loadKey($pubCert, false, true);
    echo "LOAD_CERT: not rejected\n";
} catch (Exception $e) {
    echo "LOAD_CERT: ".$e->getMessage()."\n";
}

/* 3) A genuine shared-secret HMAC key still works. */
$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->loadKey('secret-hmac-key-material');
$data = 'signed-payload';
$sig = $key->signData($data);
echo "HMAC_OK: ".($key->verifySignature($data, $sig) === 1 ? "yes" : "no")."\n";
?>
--EXPECTF--
LOAD_PEM: Asymmetric key material cannot be used as an HMAC key
LOAD_CERT: An X.509 certificate cannot be used as an HMAC key
HMAC_OK: yes
