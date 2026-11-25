--TEST--
Signature verification defaults to the SHA-2 SignatureMethod/DigestMethod lists
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
    if ($sigAlg === XMLSecurityKey::HMAC_SHA1) {
        $key->loadKey('dsig-default-algorithms-shared-secret');
    } else {
        $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    }
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

function verifyKey($sigAlg) {
    $key = new XMLSecurityKey($sigAlg, array('type' => 'public'));
    if ($sigAlg === XMLSecurityKey::HMAC_SHA1) {
        $key->loadKey('dsig-default-algorithms-shared-secret');
    } else {
        $key->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    }
    return $key;
}

/* Low-level flow: locateSignature / validateReference / verify. */
function lowLevel($xml, $sigAlg, $configure = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if ($configure) {
        $configure($dsig);
    }
    try {
        $dsig->locateSignature($doc);
        $dsig->canonicalizeSignedInfo();
        $dsig->validateReference();
        return $dsig->verify(verifyKey($sigAlg)) === 1 ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

function highLevel($xml, $sigAlg, $configure = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if ($configure) {
        $configure($dsig);
    }
    try {
        return count($dsig->verifyDocument(verifyKey($sigAlg), $doc)) > 0 ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

$legacy = function ($d) { $d->enableLegacyMode(); };
$nullLists = function ($d) { $d->allowedSignatureAlgorithms = null; $d->allowedDigestAlgorithms = null; };

/* Defaults. */
$d = new XMLSecurityDSig();
echo 'DEFAULT_SIG: ', ($d->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS ? 'yes' : 'no'), "\n";
echo 'DEFAULT_DIG: ', ($d->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS ? 'yes' : 'no'), "\n";

/* Signing is unaffected by the verification lists (SHA-1 still signs). */
$sha256 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256);
$sha512 = signDoc(XMLSecurityKey::RSA_SHA512, XMLSecurityDSig::SHA512);
$rsaSha1 = signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256);
$digSha1 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1);
$hmacSha1 = signDoc(XMLSecurityKey::HMAC_SHA1, XMLSecurityDSig::SHA256);
$ripemd = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::RIPEMD160);
echo "SIGNED: ok\n";

echo 'SHA256 low: ', lowLevel($sha256, XMLSecurityKey::RSA_SHA256), "\n";
echo 'SHA256 doc: ', highLevel($sha256, XMLSecurityKey::RSA_SHA256), "\n";
echo 'SHA512 low: ', lowLevel($sha512, XMLSecurityKey::RSA_SHA512), "\n";
echo 'RSA-SHA1 low: ', lowLevel($rsaSha1, XMLSecurityKey::RSA_SHA1), "\n";
echo 'RSA-SHA1 doc: ', highLevel($rsaSha1, XMLSecurityKey::RSA_SHA1), "\n";
echo 'DIG-SHA1 low: ', lowLevel($digSha1, XMLSecurityKey::RSA_SHA256), "\n";
echo 'DIG-SHA1 doc: ', highLevel($digSha1, XMLSecurityKey::RSA_SHA256), "\n";
echo 'HMAC-SHA1 low: ', lowLevel($hmacSha1, XMLSecurityKey::HMAC_SHA1), "\n";
echo 'RIPEMD low: ', lowLevel($ripemd, XMLSecurityKey::RSA_SHA256), "\n";

/* enableLegacyMode() adds the SHA-1 algorithms (not RIPEMD-160). */
echo 'LEGACY RSA-SHA1 low: ', lowLevel($rsaSha1, XMLSecurityKey::RSA_SHA1, $legacy), "\n";
echo 'LEGACY RSA-SHA1 doc: ', highLevel($rsaSha1, XMLSecurityKey::RSA_SHA1, $legacy), "\n";
echo 'LEGACY DIG-SHA1 low: ', lowLevel($digSha1, XMLSecurityKey::RSA_SHA256, $legacy), "\n";
echo 'LEGACY DIG-SHA1 doc: ', highLevel($digSha1, XMLSecurityKey::RSA_SHA256, $legacy), "\n";
echo 'LEGACY HMAC-SHA1 low: ', lowLevel($hmacSha1, XMLSecurityKey::HMAC_SHA1, $legacy), "\n";
echo 'LEGACY SHA256 low: ', lowLevel($sha256, XMLSecurityKey::RSA_SHA256, $legacy), "\n";
echo 'LEGACY RIPEMD low: ', lowLevel($ripemd, XMLSecurityKey::RSA_SHA256, $legacy), "\n";

$d = new XMLSecurityDSig();
$d->enableLegacyMode();
$d->enableLegacyMode();
echo 'LEGACY SIG LIST: ', ($d->allowedSignatureAlgorithms === array_merge(XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS, array(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::DSA_SHA1, XMLSecurityKey::HMAC_SHA1)) ? 'yes' : 'no'), "\n";
echo 'LEGACY DIG LIST: ', ($d->allowedDigestAlgorithms === array(XMLSecurityDSig::SHA256, XMLSecurityDSig::SHA384, XMLSecurityDSig::SHA512, XMLSecurityDSig::SHA1) ? 'yes' : 'no'), "\n";

/* enableLegacyMode() leaves null lists null. */
$d = new XMLSecurityDSig();
$d->allowedSignatureAlgorithms = null;
$d->allowedDigestAlgorithms = null;
$d->enableLegacyMode();
echo 'LEGACY NULL: ', ($d->allowedSignatureAlgorithms === null && $d->allowedDigestAlgorithms === null ? 'yes' : 'no'), "\n";

/* Null lists apply no allowlist, in both flows. */
echo 'NULL RSA-SHA1 low: ', lowLevel($rsaSha1, XMLSecurityKey::RSA_SHA1, $nullLists), "\n";
echo 'NULL RSA-SHA1 doc: ', highLevel($rsaSha1, XMLSecurityKey::RSA_SHA1, $nullLists), "\n";
echo 'NULL DIG-SHA1 doc: ', highLevel($digSha1, XMLSecurityKey::RSA_SHA256, $nullLists), "\n";
echo 'NULL RIPEMD low: ', lowLevel($ripemd, XMLSecurityKey::RSA_SHA256, $nullLists), "\n";

/* A null list only lifts its own restriction. */
echo 'NULL SIG ONLY: ', lowLevel(signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA1), XMLSecurityKey::RSA_SHA1,
    function ($d) { $d->allowedSignatureAlgorithms = null; }), "\n";
echo 'NULL DIG ONLY: ', lowLevel(signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA1), XMLSecurityKey::RSA_SHA1,
    function ($d) { $d->allowedDigestAlgorithms = null; }), "\n";

/* Custom lists replace the defaults. */
echo 'CUSTOM SIG narrow: ', lowLevel($sha256, XMLSecurityKey::RSA_SHA256,
    function ($d) { $d->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA512); }), "\n";
echo 'CUSTOM DIG narrow: ', highLevel($sha256, XMLSecurityKey::RSA_SHA256,
    function ($d) { $d->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA512); }), "\n";
echo 'CUSTOM DIG add sha1: ', lowLevel($digSha1, XMLSecurityKey::RSA_SHA256,
    function ($d) { $d->allowedDigestAlgorithms[] = XMLSecurityDSig::SHA1; }), "\n";
echo 'CUSTOM SIG add rsa-sha1: ', highLevel($rsaSha1, XMLSecurityKey::RSA_SHA1,
    function ($d) { $d->allowedSignatureAlgorithms[] = XMLSecurityKey::RSA_SHA1; }), "\n";
echo 'CUSTOM RIPEMD: ', lowLevel($ripemd, XMLSecurityKey::RSA_SHA256,
    function ($d) { $d->allowedDigestAlgorithms[] = XMLSecurityDSig::RIPEMD160; }), "\n";
?>
--EXPECTF--
DEFAULT_SIG: yes
DEFAULT_DIG: yes
SIGNED: ok
SHA256 low: OK
SHA256 doc: OK
SHA512 low: OK
RSA-SHA1 low: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
RSA-SHA1 doc: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
DIG-SHA1 low: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
DIG-SHA1 doc: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
HMAC-SHA1 low: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
RIPEMD low: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#ripemd160'
LEGACY RSA-SHA1 low: OK
LEGACY RSA-SHA1 doc: OK
LEGACY DIG-SHA1 low: OK
LEGACY DIG-SHA1 doc: OK
LEGACY HMAC-SHA1 low: OK
LEGACY SHA256 low: OK
LEGACY RIPEMD low: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#ripemd160'
LEGACY SIG LIST: yes
LEGACY DIG LIST: yes
LEGACY NULL: yes
NULL RSA-SHA1 low: OK
NULL RSA-SHA1 doc: OK
NULL DIG-SHA1 doc: OK
NULL RIPEMD low: OK
NULL SIG ONLY: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
NULL DIG ONLY: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
CUSTOM SIG narrow: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
CUSTOM DIG narrow: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#sha256'
CUSTOM DIG add sha1: OK
CUSTOM SIG add rsa-sha1: OK
CUSTOM RIPEMD: OK
