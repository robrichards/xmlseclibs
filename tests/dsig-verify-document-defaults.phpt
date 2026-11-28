--TEST--
verifyDocument() applies the configured algorithm lists unchanged
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function signDoc($sigAlg, $digestAlg) {
    $doc = new DOMDocument();
    $doc->loadXML('<Root xmlns="urn:test"><Item>payload</Item></Root>');
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->addReference($doc, $digestAlg, array(XMLSecurityDSig::ENVELOPED), array('force_uri' => true));
    $key = new XMLSecurityKey($sigAlg, array('type' => 'private'));
    $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

function pinnedKey($sigAlg) {
    $key = new XMLSecurityKey($sigAlg, array('type' => 'public'));
    $key->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $key;
}

function runDoc($xml, $sigAlg, $configure) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $configure($dsig);
    try {
        $result = count($dsig->verifyDocument(pinnedKey($sigAlg), $doc)) > 0 ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        $result = $e->getMessage();
    }
    return array($result, $dsig);
}

$sha256 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256);
$digSha1 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1);
$rsaSha1 = signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256);

/* Default lists: a SHA-1 Reference is rejected and the properties are untouched. */
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) {
});
echo 'DEFAULT DIGEST: ', $result, "\n";
echo 'DEFAULT DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS ? 'default' : 'changed'), "\n";
echo 'DEFAULT DIGEST SIG PROP: ', ($dsig->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS ? 'default' : 'changed'), "\n";

/* Explicit digest list including SHA-1 (and SHA-256) verifies. */
$explicitDigests = array(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA1);
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) use ($explicitDigests) {
    $d->allowedDigestAlgorithms = $explicitDigests;
});
echo 'EXPLICIT DIGEST: ', $result, "\n";
echo 'EXPLICIT DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === $explicitDigests ? 'same' : 'changed'), "\n";

/* Default lists: RSA-SHA1 is rejected and the properties are untouched. */
list($result, $dsig) = runDoc($rsaSha1, XMLSecurityKey::RSA_SHA1, function ($d) {
});
echo 'DEFAULT SIG: ', $result, "\n";
echo 'DEFAULT SIG PROP: ', ($dsig->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS ? 'default' : 'changed'), "\n";
echo 'DEFAULT SIG DIG PROP: ', ($dsig->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS ? 'default' : 'changed'), "\n";

/* Explicit signature list including RSA-SHA1 verifies. */
$explicitSigs = array(XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA1);
list($result, $dsig) = runDoc($rsaSha1, XMLSecurityKey::RSA_SHA1, function ($d) use ($explicitSigs) {
    $d->allowedSignatureAlgorithms = $explicitSigs;
});
echo 'EXPLICIT SIG: ', $result, "\n";
echo 'EXPLICIT SIG PROP: ', ($dsig->allowedSignatureAlgorithms === $explicitSigs ? 'same' : 'changed'), "\n";

/* Default algorithms verify with the default lists. */
list($result, $dsig) = runDoc($sha256, XMLSecurityKey::RSA_SHA256, function ($d) {
});
echo 'DEFAULTS: ', $result, "\n";

/* An empty list is used unchanged and does not fall back to the defaults. */
list($result, $dsig) = runDoc($sha256, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->allowedDigestAlgorithms = array();
});
echo 'EMPTY DIGEST: ', $result, "\n";
echo 'EMPTY DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === array() ? 'empty' : 'other'), "\n";

/* Legacy mode extends the lists that verifyDocument() applies. */
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->enableLegacyMode();
});
echo 'LEGACY DIGEST: ', $result, "\n";
list($result, $dsig) = runDoc($rsaSha1, XMLSecurityKey::RSA_SHA1, function ($d) {
    $d->enableLegacyMode();
});
echo 'LEGACY SIG: ', $result, "\n";
?>
--EXPECTF--
DEFAULT DIGEST: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
DEFAULT DIGEST PROP: default
DEFAULT DIGEST SIG PROP: default
EXPLICIT DIGEST: OK
EXPLICIT DIGEST PROP: same
DEFAULT SIG: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
DEFAULT SIG PROP: default
DEFAULT SIG DIG PROP: default
EXPLICIT SIG: OK
EXPLICIT SIG PROP: same
DEFAULTS: OK
EMPTY DIGEST: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#sha256'
EMPTY DIGEST PROP: empty
LEGACY DIGEST: OK
LEGACY SIG: OK
