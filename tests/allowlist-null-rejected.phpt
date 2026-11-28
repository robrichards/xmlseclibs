--TEST--
Algorithm allowlists are always arrays: null is rejected and every verification path applies the same lists
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Throwable $e) {
        echo "$name: ".get_class($e).': '.$e->getMessage()."\n";
    }
}

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

function verifyKey($sigAlg) {
    $key = new XMLSecurityKey($sigAlg, array('type' => 'public'));
    $key->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $key;
}

/* Run the three verification entry points with the same configuration. */
function paths($xml, $sigAlg, $configure) {
    $out = array();
    $paths = array(
        'verify' => function ($dsig, $doc) use ($sigAlg) {
            $dsig->locateSignature($doc);
            $dsig->canonicalizeSignedInfo();
            return $dsig->verify(verifyKey($sigAlg)) === 1 ? 'OK' : 'FAIL';
        },
        'validateDigest' => function ($dsig, $doc) {
            $dsig->locateSignature($doc);
            $ref = $dsig->sigNode->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Reference')->item(0);
            $dsig->validateDigest($ref, 'data'); /* policy check only; the digest value itself does not match */
            return 'OK';
        },
        'verifyDocument' => function ($dsig, $doc) use ($sigAlg) {
            return count($dsig->verifyDocument(verifyKey($sigAlg), $doc)) > 0 ? 'OK' : 'FAIL';
        },
    );
    foreach ($paths as $name => $run) {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $dsig = new XMLSecurityDSig();
        $configure($dsig);
        try {
            $out[] = "$name=".$run($dsig, $doc);
        } catch (Exception $e) {
            $out[] = "$name=".$e->getMessage();
        }
    }
    return implode(' | ', $out);
}

/* 1. Null is rejected for every property and the old value is kept. */
attempt('DSIG SIG NULL', function () {
    $d = new XMLSecurityDSig();
    $d->allowedSignatureAlgorithms = null;
    return 'accepted';
});
attempt('DSIG DIGEST NULL', function () {
    $d = new XMLSecurityDSig();
    $d->allowedDigestAlgorithms = null;
    return 'accepted';
});
attempt('ENC KEY NULL', function () {
    $e = new XMLSecEnc();
    $e->allowedKeyAlgorithms = null;
    return 'accepted';
});
attempt('ENC DATA NULL', function () {
    $e = new XMLSecEnc();
    $e->allowedDataAlgorithms = null;
    return 'accepted';
});
$d = new XMLSecurityDSig();
$e = new XMLSecEnc();
try { $d->allowedSignatureAlgorithms = null; } catch (TypeError $t) {}
try { $d->allowedDigestAlgorithms = null; } catch (TypeError $t) {}
try { $e->allowedKeyAlgorithms = null; } catch (TypeError $t) {}
try { $e->allowedDataAlgorithms = null; } catch (TypeError $t) {}
echo 'KEPT: '.($d->allowedSignatureAlgorithms === XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS
    && $d->allowedDigestAlgorithms === XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS
    && $e->allowedKeyAlgorithms === XMLSecEnc::DEFAULT_KEY_ALGORITHMS
    && $e->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS ? 'yes' : 'no')."\n";

/* A non-array is rejected the same way. */
attempt('DSIG SIG STRING', function () {
    $d = new XMLSecurityDSig();
    $d->allowedSignatureAlgorithms = XMLSecurityKey::RSA_SHA256;
    return 'accepted';
});

/* The static entry points reject null too. */
$doc = new DOMDocument();
$doc->loadXML('<Root xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptedKey/></Root>');
$encKey = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
attempt('STATIC FROM KEY NULL', function () use ($encKey) {
    return XMLSecurityKey::fromEncryptedKeyElement($encKey, 0, false, null)->getAlgorithm();
});
attempt('STATIC FROM DATA NULL', function () use ($encKey) {
    return XMLSecurityKey::fromEncryptedKeyElement($encKey, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, null)->getAlgorithm();
});
attempt('STATIC LOCATE KEY NULL', function () use ($encKey) {
    return XMLSecEnc::staticLocateKeyInfo(null, $encKey, 0, false, null);
});
attempt('STATIC LOCATE DATA NULL', function () use ($encKey) {
    return XMLSecEnc::staticLocateKeyInfo(null, $encKey, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, null);
});

/* 2. The explicit "everything" lists are documented constants. */
echo 'SUPPORTED SIG: '.(XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS === array_merge(
    XMLSecurityDSig::DEFAULT_SIGNATURE_ALGORITHMS, XMLSecurityDSig::LEGACY_SIGNATURE_ALGORITHMS) ? 'yes' : 'no')."\n";
echo 'SUPPORTED DIGEST: '.(XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS === array_merge(
    XMLSecurityDSig::DEFAULT_DIGEST_ALGORITHMS, XMLSecurityDSig::LEGACY_DIGEST_ALGORITHMS, array(XMLSecurityDSig::RIPEMD160)) ? 'yes' : 'no')."\n";
echo 'SUPPORTED KEY: '.(XMLSecEnc::SUPPORTED_KEY_ALGORITHMS === array_merge(
    XMLSecEnc::DEFAULT_KEY_ALGORITHMS, array(XMLSecurityKey::RSA_1_5)) ? 'yes' : 'no')."\n";
echo 'SUPPORTED DATA: '.(XMLSecEnc::SUPPORTED_DATA_ALGORITHMS === array_merge(
    XMLSecEnc::DEFAULT_DATA_ALGORITHMS, XMLSecEnc::LEGACY_DATA_ALGORITHMS) ? 'yes' : 'no')."\n";

/* 3. The three paths agree for the defaults, an explicit wider list and the empty list. */
$sha256 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256);
$rsaSha1 = signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256);
$digSha1 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1);
$ripemd = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::RIPEMD160);
$none = function ($d) {};
$wide = function ($d) {
    $d->allowedSignatureAlgorithms = XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS;
    $d->allowedDigestAlgorithms = XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS;
};
$empty = function ($d) {
    $d->allowedSignatureAlgorithms = array();
    $d->allowedDigestAlgorithms = array();
};
echo "DEFAULT SHA256: ".paths($sha256, XMLSecurityKey::RSA_SHA256, $none)."\n";
echo "DEFAULT RSA-SHA1: ".paths($rsaSha1, XMLSecurityKey::RSA_SHA1, $none)."\n";
echo "DEFAULT DIG-SHA1: ".paths($digSha1, XMLSecurityKey::RSA_SHA256, $none)."\n";
echo "WIDE RSA-SHA1: ".paths($rsaSha1, XMLSecurityKey::RSA_SHA1, $wide)."\n";
echo "WIDE DIG-SHA1: ".paths($digSha1, XMLSecurityKey::RSA_SHA256, $wide)."\n";
echo "WIDE RIPEMD: ".paths($ripemd, XMLSecurityKey::RSA_SHA256, $wide)."\n";
echo "EMPTY SHA256: ".paths($sha256, XMLSecurityKey::RSA_SHA256, $empty)."\n";
?>
--EXPECTF--
DSIG SIG NULL: TypeError: Cannot assign null to property RobRichards\XMLSecLibs\XMLSecurityDSig::$allowedSignatureAlgorithms of type array
DSIG DIGEST NULL: TypeError: Cannot assign null to property RobRichards\XMLSecLibs\XMLSecurityDSig::$allowedDigestAlgorithms of type array
ENC KEY NULL: TypeError: Cannot assign null to property RobRichards\XMLSecLibs\XMLSecEnc::$allowedKeyAlgorithms of type array
ENC DATA NULL: TypeError: Cannot assign null to property RobRichards\XMLSecLibs\XMLSecEnc::$allowedDataAlgorithms of type array
KEPT: yes
DSIG SIG STRING: TypeError: Cannot assign string to property RobRichards\XMLSecLibs\XMLSecurityDSig::$allowedSignatureAlgorithms of type array
STATIC FROM KEY NULL: TypeError: %sfromEncryptedKeyElement(): Argument #4 ($allowedKeyAlgorithms) must be of type array, null given%s
STATIC FROM DATA NULL: TypeError: %sfromEncryptedKeyElement(): Argument #5 ($allowedDataAlgorithms) must be of type array, null given%s
STATIC LOCATE KEY NULL: TypeError: %sstaticLocateKeyInfo(): Argument #5 ($allowedKeyAlgorithms) must be of type array, null given%s
STATIC LOCATE DATA NULL: TypeError: %sstaticLocateKeyInfo(): Argument #6 ($allowedDataAlgorithms) must be of type array, null given%s
SUPPORTED SIG: yes
SUPPORTED DIGEST: yes
SUPPORTED KEY: yes
SUPPORTED DATA: yes
DEFAULT SHA256: verify=OK | validateDigest=OK | verifyDocument=OK
DEFAULT RSA-SHA1: verify=SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' | validateDigest=OK | verifyDocument=SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
DEFAULT DIG-SHA1: verify=OK | validateDigest=DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1' | verifyDocument=DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
WIDE RSA-SHA1: verify=OK | validateDigest=OK | verifyDocument=OK
WIDE DIG-SHA1: verify=OK | validateDigest=OK | verifyDocument=OK
WIDE RIPEMD: verify=OK | validateDigest=OK | verifyDocument=OK
EMPTY SHA256: verify=SignatureMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' | validateDigest=DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#sha256' | verifyDocument=SignatureMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
