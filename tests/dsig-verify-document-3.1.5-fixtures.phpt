--TEST--
verifyDocument() checks documents signed by xmlseclibs 3.1.5
--FILE--
<?php
/*
 * Fixtures under fixtures/xmlseclibs-3.1.5 were signed by xmlseclibs 3.1.5.
 * Do not regenerate them with the current library.
 */
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function pinnedKey()
{
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $key->loadKey(dirname(__FILE__) . '/fixtures/xmlseclibs-3.1.5/cert.pem', true, true);
    return $key;
}

function loadDoc($name)
{
    $doc = new DOMDocument();
    $doc->load(dirname(__FILE__) . '/fixtures/xmlseclibs-3.1.5/' . $name);
    return $doc;
}

function run($doc, $configure)
{
    $dsig = new XMLSecurityDSig();
    $configure($dsig);
    try {
        $nodes = $dsig->verifyDocument(pinnedKey(), $doc);
        $result = count($nodes) > 0 ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        $result = $e->getMessage();
    }
    return array($result, $dsig);
}

list($result, $dsig) = run(loadDoc('rsa-sha256-sha256.xml'), function ($d) {
});
echo 'SHA256 DEFAULT: ', $result, "\n";
echo 'SHA256 DEFAULT PROPS: ', ($dsig->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS
    && $dsig->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS ? 'default' : 'changed'), "\n";

list($result, $dsig) = run(loadDoc('rsa-sha256-sha1.xml'), function ($d) {
});
echo 'SHA1 DEFAULT: ', $result, "\n";

list($result, $dsig) = run(loadDoc('rsa-sha256-sha256.xml'), function ($d) {
    $d->allowedSignatureAlgorithms = XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS;
    $d->allowedDigestAlgorithms = XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS;
});
echo 'SHA256 SUPPORTED: ', $result, "\n";

list($result, $dsig) = run(loadDoc('rsa-sha256-sha1.xml'), function ($d) {
    $d->allowedDigestAlgorithms = XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS;
});
echo 'SHA1 SUPPORTED: ', $result, "\n";

$explicit = array(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA1);
list($result, $dsig) = run(loadDoc('rsa-sha256-sha1.xml'), function ($d) use ($explicit) {
    $d->allowedDigestAlgorithms = $explicit;
});
echo 'SHA1 EXPLICIT: ', $result, "\n";
echo 'SHA1 EXPLICIT PROP: ', ($dsig->allowedDigestAlgorithms === $explicit ? 'same' : 'changed'), "\n";

/* Default digest list plus enableLegacyMode() adds SHA-1, so the fixture verifies. */
$legacy = new XMLSecurityDSig();
$legacy->enableLegacyMode();
try {
    $legacyNodes = $legacy->verifyDocument(pinnedKey(), loadDoc('rsa-sha256-sha1.xml'));
    echo 'SHA1 LEGACY: ', (count($legacyNodes) === 1 ? 'OK' : 'FAIL '.count($legacyNodes)), "\n";
} catch (Exception $e) {
    echo 'SHA1 LEGACY: ', $e->getMessage(), "\n";
}

$tampered = loadDoc('rsa-sha256-sha256.xml');
$tampered->getElementsByTagName('Item')->item(0)->textContent = 'changed';
list($result, $dsig) = run($tampered, function ($d) {
    $d->allowedSignatureAlgorithms = XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS;
    $d->allowedDigestAlgorithms = XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS;
});
echo 'TAMPER: ', $result, "\n";
?>
--EXPECTF--
SHA256 DEFAULT: OK
SHA256 DEFAULT PROPS: default
SHA1 DEFAULT: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
SHA256 SUPPORTED: OK
SHA1 SUPPORTED: OK
SHA1 EXPLICIT: OK
SHA1 EXPLICIT PROP: same
SHA1 LEGACY: OK
TAMPER: Reference validation failed
