--TEST--
HMAC verify returns 1 on success
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->loadKey('secret-hmac-key-material');
$data = 'signed-payload';
$sig = $key->signData($data);
$ok = $key->verifySignature($data, $sig);
$bad = $key->verifySignature($data, $sig . 'x');
echo ($ok === 1 ? 'OK' : 'FAIL')."\n";
echo ($bad === 0 ? 'OK' : 'FAIL')."\n";
?>
--EXPECTF--
OK
OK
