--TEST--
Certificate thumbprint check
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$thumbprint = $siteKey->getX509Thumbprint();
echo $thumbprint."\n";
echo base64_encode($thumbprint)."\n";

$certPem = file_get_contents(dirname(__FILE__) . '/mycert.pem');
$x509 = new X509();
if (! is_array($x509->loadX509($certPem))) {
    throw new Exception('unable to load test certificate');
}
$siteKey->loadKey($x509->getPublicKey()->toString('PKCS8'));
echo 'AFTER_RAW_CERT: '.($siteKey->getX509Certificate() === null ? 'null' : 'set')."\n";
echo 'AFTER_RAW_THUMB: '.($siteKey->getX509Thumbprint() === null ? 'null' : 'set')."\n";

$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
$keptCert = $siteKey->getX509Certificate();
$keptThumb = $siteKey->getX509Thumbprint();
try {
    $siteKey->loadKey('not-a-certificate', false, true);
    echo "FAIL_LOAD: not rejected\n";
} catch (Exception $e) {
    echo "FAIL_LOAD: rejected\n";
}
echo 'FAIL_CERT: '.($siteKey->getX509Certificate() === $keptCert ? 'same' : 'changed')."\n";
echo 'FAIL_THUMB: '.($siteKey->getX509Thumbprint() === $keptThumb && $keptThumb === $thumbprint ? 'same' : 'changed')."\n";
?>
--EXPECTF--
8b600d9155e8e8dfa3c10998f736be086e83ef3b
OGI2MDBkOTE1NWU4ZThkZmEzYzEwOTk4ZjczNmJlMDg2ZTgzZWYzYg==
AFTER_RAW_CERT: null
AFTER_RAW_THUMB: null
FAIL_LOAD: rejected
FAIL_CERT: same
FAIL_THUMB: same
