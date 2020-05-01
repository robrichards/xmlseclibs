--TEST--
Basic tests for key verification against CA.
--FILE--
<?php
require(dirname(__FILE__) . '/../../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

$certDir = dirname(__FILE__) . '/../certs/';

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$objKey->loadKey($certDir . 'xmlseclibs.crt', true, true);

if ($objKey->verify($certDir . 'xmlseclibsCA.pem')) {
    echo "Key is Valid\n";
} else {
    echo "Key is NOT Valid\n";
}

if ($objKey->verify($certDir . 'xmlseclibs2CA.pem')) {
    echo "Key is Valid\n";
} else {
    echo "Key is NOT Valid\n";
}


$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$objKey->loadKey($certDir . 'xmlseclibs2.crt', true, true);

if ($objKey->verify($certDir . 'xmlseclibs2CA.pem')) {
    echo "Key is Valid\n";
} else {
    echo "Key is NOT Valid\n";
}

if ($objKey->verify($certDir . 'xmlseclibsCA.pem')) {
    echo "Key is Valid\n";
} else {
    echo "Key is NOT Valid\n";
}

?>
--EXPECTF--
Key is Valid
Key is NOT Valid
Key is Valid
Key is NOT Valid
