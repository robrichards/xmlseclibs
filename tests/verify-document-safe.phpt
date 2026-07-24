--TEST--
verifyDocument() safe-by-default verification and algorithm allowlist
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function pinnedKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

/* 1. Happy path: strong algorithms + pinned key. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
$objXMLSecDSig = new XMLSecurityDSig();
try {
    $nodes = $objXMLSecDSig->verifyDocument(pinnedKey(), $doc);
    print "VALID: ".(count($nodes) > 0 ? "yes" : "no")."\n";
} catch (Exception $e) {
    print "VALID: ".$e->getMessage()."\n";
}

/* 2. Downgrade rejected: SHA-1 signature is not in the default allowlist. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-basic-test.xml');
$objXMLSecDSig = new XMLSecurityDSig();
try {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    $objXMLSecDSig->verifyDocument($objKey, $doc);
    print "DOWNGRADE: unexpected success\n";
} catch (Exception $e) {
    print "DOWNGRADE: ".$e->getMessage()."\n";
}

/* 3. A key must be supplied; KeyInfo is never trusted implicitly. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.xml');
$objXMLSecDSig = new XMLSecurityDSig();
try {
    $objXMLSecDSig->verifyDocument(null, $doc);
    print "NOKEY: unexpected success\n";
} catch (Exception $e) {
    print "NOKEY: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
VALID: yes
DOWNGRADE: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
NOKEY: A trusted key must be supplied to verifyDocument()
