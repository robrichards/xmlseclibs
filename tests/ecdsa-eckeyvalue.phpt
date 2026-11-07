--TEST--
ECKeyValue (XML Signature 1.1): write the public key into KeyInfo and read it back
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function signWithECKeyValue($algorithm, $keyFile) {
    $doc = new DOMDocument();
    $doc->load(dirname(__FILE__) . '/basic-doc.xml');
    $objDSig = new XMLSecurityDSig();
    $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $objDSig->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::ENVELOPED));
    $objKey = new XMLSecurityKey($algorithm, array('type' => 'private'));
    $objKey->loadKey(dirname(__FILE__) . '/' . $keyFile, true);
    $objDSig->sign($objKey);
    $objDSig->addECKeyValue($objKey);
    $objDSig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

/* Verify using only the key found in the document's KeyInfo. */
function verifyFromKeyInfo($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $objXMLSecDSig = new XMLSecurityDSig();
    $objDSig = $objXMLSecDSig->locateSignature($doc);
    $objXMLSecDSig->canonicalizeSignedInfo();
    $objXMLSecDSig->validateReference();
    $objKey = $objXMLSecDSig->locateKey();
    XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
    return $objXMLSecDSig->verify($objKey);
}

/* The X coordinate of ec-p256-shortx-key.pem starts with a zero byte; the
 * point must still be written with full-width coordinates. */
$arTests = array(
    'ec-p256-key.pem' => XMLSecurityKey::ECDSA_SHA256,
    'ec-p256-shortx-key.pem' => XMLSecurityKey::ECDSA_SHA256,
    'ec-p384-key.pem' => XMLSecurityKey::ECDSA_SHA384,
    'ec-p521-key.pem' => XMLSecurityKey::ECDSA_SHA512,
);
$signedP256 = null;
foreach ($arTests AS $keyFile => $algorithm) {
    $signed = signWithECKeyValue($algorithm, $keyFile);
    if ($signedP256 === null) {
        $signedP256 = $signed;
    }
    $doc = new DOMDocument();
    $doc->loadXML($signed);
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
    $xpath->registerNamespace('dsig11', XMLSecurityDSig::XMLDSIG11NS);
    $curve = $xpath->evaluate('string(//ds:KeyInfo/ds:KeyValue/dsig11:ECKeyValue/dsig11:NamedCurve/@URI)');
    $point = base64_decode($xpath->evaluate('string(//ds:KeyInfo/ds:KeyValue/dsig11:ECKeyValue/dsig11:PublicKey)'));
    print "$keyFile: $curve, point " . strlen($point) . " bytes, verify " . verifyFromKeyInfo($signed) . "\n";
}

/* Invalid ECKeyValue content is rejected. */
$doc = new DOMDocument();
$doc->loadXML($signedP256);
$xpath = new DOMXPath($doc);
$xpath->registerNamespace('dsig11', XMLSecurityDSig::XMLDSIG11NS);
$publicKey = $xpath->query('//dsig11:PublicKey')->item(0)->textContent;
$point = base64_decode($publicKey);

$offCurve = $point;
$offCurve[64] = chr(ord($offCurve[64]) ^ 1);
$compressed = chr(2 + (ord($point[64]) & 1)) . substr($point, 1, 32);

$arInvalid = array(
    'off-curve point' => array('PublicKey', base64_encode($offCurve)),
    'compressed point' => array('PublicKey', base64_encode($compressed)),
    'truncated point' => array('PublicKey', base64_encode(substr($point, 0, 64))),
    'unsupported curve' => array('URI', 'urn:oid:1.3.132.0.10'),
    'not an OID URI' => array('URI', 'http://example.com/curve'),
    'invalid base64' => array('PublicKey', '!not base64!'),
    'missing PublicKey' => array('Element', ''),
);
foreach ($arInvalid AS $label => $change) {
    if ($change[0] === 'Element') {
        $xml = preg_replace('#<dsig11:PublicKey>[^<]*</dsig11:PublicKey>#', '', $signedP256);
    } elseif ($change[0] === 'URI') {
        $xml = str_replace('URI="urn:oid:1.2.840.10045.3.1.7"', 'URI="' . $change[1] . '"', $signedP256);
    } else {
        $xml = str_replace($publicKey, $change[1], $signedP256);
    }
    try {
        print "$label: unexpected result " . verifyFromKeyInfo($xml) . "\n";
    } catch (Exception $e) {
        print "$label: " . $e->getMessage() . "\n";
    }
}

/* ECKeyValue can not be produced from an RSA key. */
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
try {
    $objKey->getECPublicKeyData();
    print "RSA key: unexpected success\n";
} catch (Exception $e) {
    print "RSA key: " . $e->getMessage() . "\n";
}
?>
--EXPECTF--
ec-p256-key.pem: urn:oid:1.2.840.10045.3.1.7, point 65 bytes, verify 1
ec-p256-shortx-key.pem: urn:oid:1.2.840.10045.3.1.7, point 65 bytes, verify 1
ec-p384-key.pem: urn:oid:1.3.132.0.34, point 97 bytes, verify 1
ec-p521-key.pem: urn:oid:1.3.132.0.35, point 133 bytes, verify 1
off-curve point: Unable to convert EC key
compressed point: Unable to convert EC key
truncated point: Unable to convert EC key
unsupported curve: Unsupported ECKeyValue curve
not an OID URI: Unsupported NamedCurve URI
invalid base64: Invalid ECKeyValue PublicKey
missing PublicKey: Missing NamedCurve or PublicKey
RSA key: Expected an EC key
