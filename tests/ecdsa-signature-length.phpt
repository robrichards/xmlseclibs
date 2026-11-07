--TEST--
ECDSA r || s length: signatures are full width; shortened values are accepted, odd or overlong values are rejected
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* Some signers (e.g. Apache Santuario) strip leading zero bytes from r and s
 * before concatenating them, so P-521 signatures are sometimes 130 bytes
 * instead of 132. Find a signature whose r and s both start with a zero byte
 * and shorten it the same way. */
$signer = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'private'));
$signer->loadKey(dirname(__FILE__) . '/ec-p521-key.pem', true);
$verifier = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'public'));
$verifier->loadKey(dirname(__FILE__) . '/ec-p521-cert.pem', true, true);

/* Generated signatures are always 2 x 66 bytes, even when r or s is
 * shorter (phpseclib < 3.0.40 produced 130/131-byte P-521 signatures). */
$lengths = array();
$signature = null;
for ($i = 0; $i < 200; $i++) {
    $data = "message $i";
    $candidate = $signer->signData($data);
    $lengths[strlen($candidate)] = true;
    if ($signature === null && $candidate[0] === "\0" && $candidate[66] === "\0") {
        $signature = $candidate;
        $signedData = $data;
    }
}
print "generated lengths: " . implode(', ', array_keys($lengths)) . "\n";
$data = $signedData;
print "full width (" . strlen($signature) . "): " . $verifier->verifySignature($data, $signature) . "\n";

$shortened = substr($signature, 1, 65) . substr($signature, 67);
print "shortened (" . strlen($shortened) . "): " . $verifier->verifySignature($data, $shortened) . "\n";

$odd = substr($signature, 1);
print "odd length (" . strlen($odd) . "): " . $verifier->verifySignature($data, $odd) . "\n";

$overlong = "\0" . substr($signature, 0, 66) . "\0" . substr($signature, 66);
print "overlong (" . strlen($overlong) . "): " . $verifier->verifySignature($data, $overlong) . "\n";

print "empty: " . $verifier->verifySignature($data, '') . "\n";
?>
--EXPECTF--
generated lengths: 132
full width (132): 1
shortened (130): 1
odd length (131): 0
overlong (134): 0
empty: 0
