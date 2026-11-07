--TEST--
ECDSA curve allowlist: only P-256, P-384 and P-521 by default; other curves must be added explicitly
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$data = 'data to sign';
$secp256k1 = array('secp256k1' => '1.3.132.0.10');

function ecKey($type, $file, $allowedCurves = null) {
    $objKey = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => $type));
    $objKey->allowedECCurves = $allowedCurves;
    $objKey->loadKey(dirname(__FILE__) . '/' . $file, true, $type === 'public');
    return $objKey;
}

function attempt($label, $callback) {
    try {
        print "$label: " . $callback() . "\n";
    } catch (Exception $e) {
        print "$label: " . $e->getMessage() . "\n";
    }
}

/* Default allowlist: secp256k1 is rejected for signing, verifying and ECKeyValue. */
attempt('default sign secp256k1', function () use ($data) {
    ecKey('private', 'ec-secp256k1-key.pem')->signData($data);
    return 'signed';
});
attempt('default ECKeyValue secp256k1', function () {
    ecKey('public', 'ec-secp256k1-cert.pem')->getECPublicKeyData();
    return 'written';
});

/* Explicitly allowed: sign, verify and write ECKeyValue. */
$allowed = XMLSecurityKey::EC_CURVE_OIDS + $secp256k1;
$signature = ecKey('private', 'ec-secp256k1-key.pem', $allowed)->signData($data);
print "allowed sign secp256k1: " . strlen($signature) . " bytes\n";
print "allowed verify secp256k1: " . ecKey('public', 'ec-secp256k1-cert.pem', $allowed)->verifySignature($data, $signature) . "\n";
print "default verify secp256k1: " . ecKey('public', 'ec-secp256k1-cert.pem')->verifySignature($data, $signature) . "\n";

/* A narrower allowlist rejects default curves too. */
attempt('P-256 only, sign P-384', function () use ($data) {
    ecKey('private', 'ec-p384-key.pem', array('secp256r1' => '1.2.840.10045.3.1.7'))->signData($data);
    return 'signed';
});

/* EdDSA keys are rejected even if allowlisted. */
attempt('allowlisted Ed25519', function () use ($data) {
    ecKey('private', 'ed25519-key.pem', array('Ed25519' => '1.3.101.112'))->signData($data);
    return 'signed';
});

/* ECKeyValue in KeyInfo follows the allowlist of the base key. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');
$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objDSig->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::ENVELOPED));
$signer = ecKey('private', 'ec-secp256k1-key.pem', $allowed);
$objDSig->sign($signer);
$objDSig->addECKeyValue($signer);
$objDSig->appendSignature($doc->documentElement);
$signed = $doc->saveXML();

foreach (array('default' => null, 'allowed' => $allowed) as $label => $curves) {
    attempt("KeyInfo ECKeyValue secp256k1, $label", function () use ($signed, $curves) {
        $doc = new DOMDocument();
        $doc->loadXML($signed);
        $objXMLSecDSig = new XMLSecurityDSig();
        $objSig = $objXMLSecDSig->locateSignature($doc);
        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->validateReference();
        $objKey = $objXMLSecDSig->locateKey();
        $objKey->allowedECCurves = $curves;
        XMLSecEnc::staticLocateKeyInfo($objKey, $objSig);
        return $objXMLSecDSig->verify($objKey);
    });
}
?>
--EXPECTF--
default sign secp256k1: EC curve is not allowed: 'secp256k1'
default ECKeyValue secp256k1: EC curve is not allowed: 'secp256k1'
allowed sign secp256k1: 64 bytes
allowed verify secp256k1: 1
default verify secp256k1: -1
P-256 only, sign P-384: EC curve is not allowed: 'secp384r1'
allowlisted Ed25519: ECDSA requires a key on a named prime curve
KeyInfo ECKeyValue secp256k1, default: Unsupported ECKeyValue curve
KeyInfo ECKeyValue secp256k1, allowed: 1
