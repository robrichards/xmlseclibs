--TEST--
ECDSA: verify signatures produced by xmlsec1, Apache Santuario and .NET SignedXml
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/*
 * Vectors in ecdsa-interop/ (test keys only):
 *  - xmlsec1 1.2.33 (OpenSSL 3.0.2)
 *  - Apache Santuario xmlsec 1.5.8 on JDK 8
 *  - .NET 8 SignedXml with a custom ECDSA SignatureDescription (IEEE P1363)
 * Santuario strips leading zero bytes from r and s, so about 1 in 4 of its
 * P-521 signatures are 130 bytes instead of 132 (the *-130bytes-* files).
 */
$dir = dirname(__FILE__) . '/ecdsa-interop';
$files = glob("$dir/*.xml");
sort($files);

function verifyVector($xml, $curve) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
    $algorithm = $xpath->evaluate('string(//ds:SignatureMethod/@Algorithm)');

    $objKey = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . "/ecdsa-interop/$curve-cert.pem", true, true);

    $objXMLSecDSig = new XMLSecurityDSig();
    $objXMLSecDSig->idKeys = array('ID');
    $nodes = $objXMLSecDSig->verifyDocument($objKey, $doc);
    return count($nodes) > 0;
}

foreach ($files AS $file) {
    $name = basename($file, '.xml');
    preg_match('/-(p256|p384|p521)-/', $name, $curveMatch);
    $xml = file_get_contents($file);

    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
    $sigLength = strlen(base64_decode($xpath->evaluate('string(//ds:SignatureValue)')));

    try {
        $result = verifyVector($xml, $curveMatch[1]) ? 'valid' : 'invalid';
    } catch (Exception $e) {
        $result = $e->getMessage();
    }
    print "$name ($sigLength): $result\n";
}

/* Negative control: the signed content was changed. */
$xml = file_get_contents("$dir/santuario-p521-sha256-empty-130bytes-1.xml");
$xml = str_replace('<doc:Fecha>2026-10-06</doc:Fecha>', '<doc:Fecha>2026-10-07</doc:Fecha>', $xml, $count);
try {
    print "tampered ($count): " . (verifyVector($xml, 'p521') ? 'valid' : 'invalid') . "\n";
} catch (Exception $e) {
    print "tampered ($count): rejected\n";
}
?>
--EXPECTF--
dotnet-p256-sha256-id (64): valid
dotnet-p384-sha384-id (96): valid
dotnet-p521-sha256-empty (132): valid
dotnet-p521-sha512-id (132): valid
santuario-p256-sha256-id (64): valid
santuario-p256-sha512-empty (64): valid
santuario-p384-sha384-id (96): valid
santuario-p521-sha256-empty-130bytes-1 (130): valid
santuario-p521-sha256-empty-130bytes-2 (130): valid
santuario-p521-sha512-id (132): valid
xmlsec1-p256-sha256-id (64): valid
xmlsec1-p384-sha384-id (96): valid
xmlsec1-p521-sha256-empty (132): valid
xmlsec1-p521-sha512-id (132): valid
tampered (1): rejected
