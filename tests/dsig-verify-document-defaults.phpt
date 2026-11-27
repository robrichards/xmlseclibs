--TEST--
verifyDocument() falls back to the default algorithm lists when a list is null
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

/* Null digest list: a SHA-1 Reference is rejected and the property stays null. */
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->allowedDigestAlgorithms = null;
});
echo 'NULL DIGEST: ', $result, "\n";
echo 'NULL DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === null ? 'null' : 'set'), "\n";
echo 'NULL DIGEST SIG PROP: ', ($dsig->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS ? 'default' : 'changed'), "\n";

/* Explicit digest list including SHA-1 (and SHA-256) verifies. */
$explicitDigests = array(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA1);
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) use ($explicitDigests) {
    $d->allowedDigestAlgorithms = $explicitDigests;
});
echo 'EXPLICIT DIGEST: ', $result, "\n";
echo 'EXPLICIT DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === $explicitDigests ? 'same' : 'changed'), "\n";

/* Null signature list: RSA-SHA1 is rejected and the property stays null. */
list($result, $dsig) = runDoc($rsaSha1, XMLSecurityKey::RSA_SHA1, function ($d) {
    $d->allowedSignatureAlgorithms = null;
});
echo 'NULL SIG: ', $result, "\n";
echo 'NULL SIG PROP: ', ($dsig->allowedSignatureAlgorithms === null ? 'null' : 'set'), "\n";
echo 'NULL SIG DIG PROP: ', ($dsig->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS ? 'default' : 'changed'), "\n";

/* Explicit signature list including RSA-SHA1 verifies. */
$explicitSigs = array(XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA1);
list($result, $dsig) = runDoc($rsaSha1, XMLSecurityKey::RSA_SHA1, function ($d) use ($explicitSigs) {
    $d->allowedSignatureAlgorithms = $explicitSigs;
});
echo 'EXPLICIT SIG: ', $result, "\n";
echo 'EXPLICIT SIG PROP: ', ($dsig->allowedSignatureAlgorithms === $explicitSigs ? 'same' : 'changed'), "\n";

/* Null lists still accept the default algorithms, then stay null. */
list($result, $dsig) = runDoc($sha256, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->allowedSignatureAlgorithms = null;
    $d->allowedDigestAlgorithms = null;
});
echo 'NULL DEFAULTS: ', $result, "\n";
echo 'NULL DEFAULTS PROPS: ', ($dsig->allowedSignatureAlgorithms === null && $dsig->allowedDigestAlgorithms === null ? 'null' : 'set'), "\n";

/* An empty list is used unchanged and does not fall back to the defaults. */
list($result, $dsig) = runDoc($sha256, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->allowedDigestAlgorithms = array();
});
echo 'EMPTY DIGEST: ', $result, "\n";
echo 'EMPTY DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === array() ? 'empty' : 'other'), "\n";

/* enableLegacyMode() leaves a null list null, so the fallback stays DEFAULT_*. */
list($result, $dsig) = runDoc($digSha1, XMLSecurityKey::RSA_SHA256, function ($d) {
    $d->allowedDigestAlgorithms = null;
    $d->enableLegacyMode();
});
echo 'LEGACY NULL DIGEST: ', $result, "\n";
echo 'LEGACY NULL DIGEST PROP: ', ($dsig->allowedDigestAlgorithms === null ? 'null' : 'set'), "\n";
?>
--EXPECTF--
NULL DIGEST: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
NULL DIGEST PROP: null
NULL DIGEST SIG PROP: default
EXPLICIT DIGEST: OK
EXPLICIT DIGEST PROP: same
NULL SIG: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
NULL SIG PROP: null
NULL SIG DIG PROP: default
EXPLICIT SIG: OK
EXPLICIT SIG PROP: same
NULL DEFAULTS: OK
NULL DEFAULTS PROPS: null
EMPTY DIGEST: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#sha256'
EMPTY DIGEST PROP: empty
LEGACY NULL DIGEST: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
LEGACY NULL DIGEST PROP: null
