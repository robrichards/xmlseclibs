--TEST--
Low-level verify() rejects SignatureMethod/key algorithm substitution (GHSA-m5mw-mr39-66vp)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function rsaPublicKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

$signed = file_get_contents(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');

/* 1. Positive control: untouched document verifies with the matching key
 * using the low-level primitives (no allowlist configured). */
$doc = new DOMDocument();
$doc->loadXML($signed);
$objXMLSecDSig = new XMLSecurityDSig();
$objXMLSecDSig->locateSignature($doc);
$objXMLSecDSig->canonicalizeSignedInfo();
$objXMLSecDSig->validateReference();
print "CONTROL: ".($objXMLSecDSig->verify(rsaPublicKey()) === 1 ? "valid" : "invalid")."\n";

/* 2. Attacker downgrades SignatureMethod to hmac-sha1 while the relying party
 * still supplies its RSA key. Even with no allowlist set, verify() must refuse
 * the algorithm/key mismatch rather than attempting HMAC with public material. */
$downgraded = str_replace(
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    $signed
);
$doc = new DOMDocument();
$doc->loadXML($downgraded);
$objXMLSecDSig = new XMLSecurityDSig();
$objXMLSecDSig->locateSignature($doc);
$objXMLSecDSig->canonicalizeSignedInfo();
try {
    $objXMLSecDSig->validateReference();
} catch (Exception $e) {
    /* Reference digests are unaffected by the SignatureMethod swap; ignore. */
}
try {
    $objXMLSecDSig->verify(rsaPublicKey());
    print "SUBST: not rejected\n";
} catch (Exception $e) {
    print "SUBST: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
CONTROL: valid
SUBST: SignatureMethod algorithm does not match the supplied key type
