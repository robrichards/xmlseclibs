--TEST--
Basic Encryption with included KeyInfo
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

if (file_exists(dirname(__FILE__) . '/oaep_sha1.xml')) {
    unlink(dirname(__FILE__) . '/oaep_sha1.xml');
}

$dom = new DOMDocument();
$dom->load(dirname(__FILE__) . '/basic-doc.xml');

$objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey->generateSessionKey();

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->encryptKey($siteKey, $objKey, true, true);

$enc->type = XMLSecEnc::Element;
$encNode = $enc->encryptNode($objKey);

$dom->save(dirname(__FILE__) . '/oaep_sha1_keyinfo.xml');

$xPath = new DOMXPath($dom);
$xPath->registerNamespace('dsig', 'http://www.w3.org/2000/09/xmldsig#');
$xPath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

$queriedNode = $xPath->query(
    '/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate'
);
if ($queriedNode->length !== 1) {
    echo 'X509Certificate not found in KeyInfo';
}
echo $queriedNode->item(0)->textContent;

unlink(dirname(__FILE__) . '/oaep_sha1_keyinfo.xml');

?>
--EXPECTF--
MIIEVDCCAzygAwIBAgIJAPTrkMJbCOr1MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVNYWluZTESMBAGA1UEBxMJTGltaW5ndG9uMR8wHQYDVQQKExZ4bWxzZWNsaWJzLnBocCBMaWJyYXJ5MSUwIwYDVQQDExx4bWxzZWNsaWJzL3d3dy5jZGF0YXpvbmUub3JnMB4XDTA4MDcwNzIwMjIzMVoXDTE4MDcwNTIwMjIzMVoweTELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBU1haW5lMRIwEAYDVQQHEwlMaW1pbmd0b24xHzAdBgNVBAoTFnhtbHNlY2xpYnMucGhwIExpYnJhcnkxJTAjBgNVBAMTHHhtbHNlY2xpYnMvd3d3LmNkYXRhem9uZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDttdMyM5ISVD1Uz+BHAPrxVJ6N1eZonfg3DMvZVT0Zy64+qcXj8zuHC6lolDsfGnD8LUttraQ7qCL+bHKps+hjAhCRdx5Wcn4iDrlFpxFL7INnr6vekzsCQ45BPUrvksF9FKa7yX4iSDButmPfoT14gPnIuSe8Y5UeGe6Lk6sF0WgHyL+JmxOu377Kuhah2pXZ1+z7V4JIlNgemJtKlqrvgGeuE9TagfGHUL9BuZK5fUx/RSDUjqxUeKU3fft9fGIAZl0dduitC2Otv4dr1gxLrUmI+ZZ75FmtfKQT7SmS92QVI2B5WAPlL1bnbvhkZiyw7nFE+Q/wGJ2myE4RIFjdAgMBAAGjgd4wgdswHQYDVR0OBBYEFEC5iG0uGXLpQG/zMj/4TuDWfTpHMIGrBgNVHSMEgaMwgaCAFEC5iG0uGXLpQG/zMj/4TuDWfTpHoX2kezB5MQswCQYDVQQGEwJVUzEOMAwGA1UECBMFTWFpbmUxEjAQBgNVBAcTCUxpbWluZ3RvbjEfMB0GA1UEChMWeG1sc2VjbGlicy5waHAgTGlicmFyeTElMCMGA1UEAxMceG1sc2VjbGlicy93d3cuY2RhdGF6b25lLm9yZ4IJAPTrkMJbCOr1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACmSKrte07VrGB8dtrN5mrt28ILickQjguu46h6vChgQ4YfIAoA1KWNsZJUuuIzTDjE5xz2hsW37CI0yrNesv2ho2hhP+fIaxCGmcwLYXL80UaPRglYk5+wPWFOt3QFAVoEgwjLX9+y+c2Gu7xLgHAFZVRjQ5hhKT0Nj3vhnt0k8LcognNl1wKuWda7VL4tODp/2IOXr5o5v/OL3UesGfeWfvr8LVmMc5f7/vLAu1+2Yk+/C9/EZyf3BDZQ4z8ae/iwqprCTUIEjhUDcq4+0YN2EIw6suGE2FtWlsIywNErmoOhdrmntU61n3nFCQBi7QDUnZrAFrl4/bmk3eRJ00nE=
