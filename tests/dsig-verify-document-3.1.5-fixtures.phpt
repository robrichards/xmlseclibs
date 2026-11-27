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
    $d->allowedSignatureAlgorithms = null;
    $d->allowedDigestAlgorithms = null;
});
echo 'SHA256 NULL: ', $result, "\n";
echo 'SHA256 NULL PROPS: ', ($dsig->allowedSignatureAlgorithms === null && $dsig->allowedDigestAlgorithms === null ? 'null' : 'set'), "\n";

list($result, $dsig) = run(loadDoc('rsa-sha256-sha1.xml'), function ($d) {
    $d->allowedDigestAlgorithms = null;
});
echo 'SHA1 NULL: ', $result, "\n";
echo 'SHA1 NULL PROP: ', ($dsig->allowedDigestAlgorithms === null ? 'null' : 'set'), "\n";

$explicit = array(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA1);
list($result, $dsig) = run(loadDoc('rsa-sha256-sha1.xml'), function ($d) use ($explicit) {
    $d->allowedDigestAlgorithms = $explicit;
});
echo 'SHA1 EXPLICIT: ', $result, "\n";
echo 'SHA1 EXPLICIT PROP: ', ($dsig->allowedDigestAlgorithms === $explicit ? 'same' : 'changed'), "\n";

$tampered = loadDoc('rsa-sha256-sha256.xml');
$tampered->getElementsByTagName('Item')->item(0)->textContent = 'changed';
list($result, $dsig) = run($tampered, function ($d) {
    $d->allowedSignatureAlgorithms = null;
    $d->allowedDigestAlgorithms = null;
});
echo 'TAMPER: ', $result, "\n";
?>
--EXPECTF--
SHA256 NULL: OK
SHA256 NULL PROPS: null
SHA1 NULL: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
SHA1 NULL PROP: null
SHA1 EXPLICIT: OK
SHA1 EXPLICIT PROP: same
TAMPER: Reference validation failed
