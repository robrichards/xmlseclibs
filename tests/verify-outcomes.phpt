--TEST--
verify() and verifySignature() return 1 or 0, and throw when verification cannot be completed
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$dir = dirname(__FILE__);
$secret = 'secret-hmac-key-material';

function signingKey($alg) {
    global $dir, $secret;
    if ($alg === XMLSecurityKey::HMAC_SHA1) {
        $key = new XMLSecurityKey($alg);
        $key->loadKey($secret);
        return $key;
    }
    $key = new XMLSecurityKey($alg, array('type' => 'private'));
    $key->loadKey($dir . '/privkey.pem', true);
    return $key;
}

function verifyingKey($alg) {
    global $dir, $secret;
    if ($alg === XMLSecurityKey::HMAC_SHA1) {
        $key = new XMLSecurityKey($alg);
        $key->loadKey($secret);
        return $key;
    }
    $key = new XMLSecurityKey($alg, array('type' => 'public'));
    $key->loadKey($dir . '/mycert.pem', true, true);
    return $key;
}

function signDoc($alg) {
    $doc = new DOMDocument();
    $doc->loadXML('<Root xmlns="urn:test"><Item>payload</Item></Root>');
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::ENVELOPED), array('force_uri' => true));
    $dsig->sign(signingKey($alg));
    $dsig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

function sigValueNode($dsig) {
    return $dsig->sigNode->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'SignatureValue')->item(0);
}

/* A verifier positioned on the signature, ready for verify(). */
function located($xml, $legacy = false) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    $dsig->locateSignature($doc);
    $dsig->canonicalizeSignedInfo();
    return $dsig;
}

/* Replace SignatureValue with a well-formed value that is a different signature. */
function mismatch($dsig) {
    $node = sigValueNode($dsig);
    $raw = base64_decode($node->textContent);
    $raw[0] = chr(ord($raw[0]) ^ 0x01);
    $node->nodeValue = base64_encode($raw);
}

function malform($dsig) {
    sigValueNode($dsig)->nodeValue = '!!not*base64!!';
}

function outcome($callback) {
    try {
        $r = $callback();
        return is_int($r) ? "int($r)" : var_export($r, true);
    } catch (Exception $e) {
        return 'throws: ' . $e->getMessage();
    }
}

/* verifySignature() directly: valid is 1, mismatched is 0. */
$data = 'signed-payload';
foreach (array(XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1) as $alg) {
    $sig = signingKey($alg)->signData($data);
    echo "$alg valid: " . outcome(function () use ($alg, $data, $sig) {
        return verifyingKey($alg)->verifySignature($data, $sig);
    }) . "\n";
    echo "$alg mismatched: " . outcome(function () use ($alg, $data, $sig) {
        return verifyingKey($alg)->verifySignature($data . 'x', $sig);
    }) . "\n";
}

echo "== former -1 paths in verifySignature()\n";
$rsa = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
echo 'RSA no key: ' . outcome(function () use ($rsa) { return $rsa->verifySignature('d', 's'); }) . "\n";
$ec = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'public'));
echo 'EC no key: ' . outcome(function () use ($ec) { return $ec->verifySignature('d', 's'); }) . "\n";

$rsa = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$rsa->key = 'not a key';
$msg = outcome(function () use ($rsa) { return $rsa->verifySignature('d', 's'); });
echo 'RSA unloadable key: ' . (strpos($msg, 'throws: Cannot verify signature: ') === 0 ? 'throws' : $msg) . "\n";
$ec = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'public'));
$ec->key = 'not a key';
$msg = outcome(function () use ($ec) { return $ec->verifySignature('d', 's'); });
echo 'EC unloadable key: ' . (strpos($msg, 'throws: Cannot verify signature: ') === 0 ? 'throws' : $msg) . "\n";

$rsa = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$rsa->key = file_get_contents($dir . '/privkey.pem');
echo 'RSA private key material: ' . outcome(function () use ($rsa) { return $rsa->verifySignature('d', 's'); }) . "\n";
$ec = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'public'));
$ec->key = file_get_contents($dir . '/ec-p256-key.pem');
echo 'EC private key material: ' . outcome(function () use ($ec) { return $ec->verifySignature('d', 's'); }) . "\n";

$rsa = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$rsa->loadKey($dir . '/ec-p256-cert.pem', true, true);
echo 'RSA with EC cert: ' . outcome(function () use ($rsa) { return $rsa->verifySignature('d', 's'); }) . "\n";
$ec = new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, array('type' => 'public'));
$ec->loadKey($dir . '/mycert.pem', true, true);
echo 'EC with RSA cert: ' . outcome(function () use ($ec) { return $ec->verifySignature('d', 's'); }) . "\n";

$hmac = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
echo 'HMAC no key: ' . outcome(function () use ($hmac) { return $hmac->verifySignature('d', 's'); }) . "\n";
$hmac = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$hmac->key = file_get_contents($dir . '/mycert.pem');
echo 'HMAC asymmetric material: ' . outcome(function () use ($hmac) { return $hmac->verifySignature('d', 's'); }) . "\n";

/* The final fallback is defensive; reach it by clearing the library parameter. */
$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->loadKey($secret);
$prop = new ReflectionProperty(XMLSecurityKey::class, 'cryptParams');
$params = $prop->getValue($key);
$params['library'] = 'none';
$prop->setValue($key, $params);
echo 'Unsupported library: ' . outcome(function () use ($key) { return $key->verifySignature('d', 's'); }) . "\n";

/* Established behaviors are unchanged. */
$oaep = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
echo 'verifySignature, non-signature key: ' . outcome(function () use ($oaep) { return $oaep->verifySignature('d', 's'); }) . "\n";
$dsig = located(signDoc(XMLSecurityKey::RSA_SHA256));
$oaep = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
$msg = outcome(function () use ($dsig, $oaep) { return $dsig->verify($oaep); });
echo 'verify(), non-signature key: ' . (strpos($msg, 'throws:') === 0 ? 'throws' : $msg) . "\n";

echo "== verify(): three outcomes (legacy mode on for the SHA-1 algorithms)\n";
foreach (array(XMLSecurityKey::RSA_SHA256, XMLSecurityKey::HMAC_SHA1, XMLSecurityKey::RSA_SHA1) as $alg) {
    $xml = signDoc($alg);
    $dsig = located($xml, $alg !== XMLSecurityKey::RSA_SHA256);
    echo "$alg verified: " . outcome(function () use ($dsig, $alg) { return $dsig->verify(verifyingKey($alg)); }) . "\n";
    $dsig = located($xml, $alg !== XMLSecurityKey::RSA_SHA256);
    mismatch($dsig);
    echo "$alg mismatch: " . outcome(function () use ($dsig, $alg) { return $dsig->verify(verifyingKey($alg)); }) . "\n";
    $dsig = located($xml, $alg !== XMLSecurityKey::RSA_SHA256);
    malform($dsig);
    echo "$alg malformed: " . outcome(function () use ($dsig, $alg) { return $dsig->verify(verifyingKey($alg)); }) . "\n";
}

echo "== validated nodes on a reused verifier\n";
function nodeCount($dsig) {
    $n = $dsig->getValidatedNodes();
    return $n === null ? 'null' : count($n);
}
foreach (array('mismatch' => 'mismatch', 'malformed' => 'malform', 'unloaded key' => null) as $label => $fn) {
    $xml = signDoc(XMLSecurityKey::RSA_SHA256);
    $dsig = located($xml);
    $key = verifyingKey(XMLSecurityKey::RSA_SHA256);
    $dsig->validateReference();
    echo "$label: after validateReference: " . nodeCount($dsig) . "\n";
    echo "$label: verify valid: " . outcome(function () use ($dsig, $key) { return $dsig->verify($key); }) . ', nodes ' . nodeCount($dsig) . "\n";
    if ($fn === 'mismatch') {
        mismatch($dsig);
    } elseif ($fn === 'malform') {
        malform($dsig);
    }
    if ($fn === null) {
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    }
    echo "$label: verify failing: " . outcome(function () use ($dsig, $key) { return $dsig->verify($key); }) . ', nodes ' . nodeCount($dsig) . "\n";
}

echo "== verifyDocument(), legacy off and on\n";
function docResult($xml, $alg, $legacy, $edit = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    if ($edit) {
        $d = new XMLSecurityDSig();
        $d->locateSignature($doc);
        $edit($d);
    }
    return outcome(function () use ($dsig, $alg, $doc) {
        return count($dsig->verifyDocument(verifyingKey($alg), $doc));
    });
}
foreach (array(XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1) as $alg) {
    $xml = signDoc($alg);
    foreach (array(0 => 'off', 1 => 'on') as $legacy => $label) {
        echo "$alg legacy $label valid: " . docResult($xml, $alg, (bool) $legacy) . "\n";
        echo "$alg legacy $label mismatch: " . docResult($xml, $alg, (bool) $legacy, 'mismatch') . "\n";
        echo "$alg legacy $label malformed: " . docResult($xml, $alg, (bool) $legacy, 'malform') . "\n";
    }
}
?>
--EXPECT--
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 valid: int(1)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 mismatched: int(0)
http://www.w3.org/2000/09/xmldsig#rsa-sha1 valid: int(1)
http://www.w3.org/2000/09/xmldsig#rsa-sha1 mismatched: int(0)
http://www.w3.org/2000/09/xmldsig#hmac-sha1 valid: int(1)
http://www.w3.org/2000/09/xmldsig#hmac-sha1 mismatched: int(0)
== former -1 paths in verifySignature()
RSA no key: throws: Cannot verify signature: no key has been loaded
EC no key: throws: Cannot verify signature: no key has been loaded
RSA unloadable key: throws
EC unloadable key: throws
RSA private key material: throws: Cannot verify signature: the key is not an RSA public key
EC private key material: throws: Cannot verify signature: the key is not an EC public key
RSA with EC cert: throws: Cannot verify signature: Expected an RSA key
EC with RSA cert: throws: Cannot verify signature: Expected an EC key
HMAC no key: throws: Cannot verify signature: no HMAC key has been loaded
HMAC asymmetric material: throws: Asymmetric key material cannot be used as an HMAC key
Unsupported library: throws: Unsupported key type for verification
verifySignature, non-signature key: int(0)
verify(), non-signature key: throws
== verify(): three outcomes (legacy mode on for the SHA-1 algorithms)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 verified: int(1)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 mismatch: int(0)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 malformed: throws: SignatureValue is not valid Base64
http://www.w3.org/2000/09/xmldsig#hmac-sha1 verified: int(1)
http://www.w3.org/2000/09/xmldsig#hmac-sha1 mismatch: int(0)
http://www.w3.org/2000/09/xmldsig#hmac-sha1 malformed: throws: SignatureValue is not valid Base64
http://www.w3.org/2000/09/xmldsig#rsa-sha1 verified: int(1)
http://www.w3.org/2000/09/xmldsig#rsa-sha1 mismatch: int(0)
http://www.w3.org/2000/09/xmldsig#rsa-sha1 malformed: throws: SignatureValue is not valid Base64
== validated nodes on a reused verifier
mismatch: after validateReference: 1
mismatch: verify valid: int(1), nodes 1
mismatch: verify failing: int(0), nodes null
malformed: after validateReference: 1
malformed: verify valid: int(1), nodes 1
malformed: verify failing: throws: SignatureValue is not valid Base64, nodes null
unloaded key: after validateReference: 1
unloaded key: verify valid: int(1), nodes 1
unloaded key: verify failing: throws: Cannot verify signature: no key has been loaded, nodes null
== verifyDocument(), legacy off and on
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy off valid: int(1)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy off mismatch: throws: Signature validation failed
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy off malformed: throws: SignatureValue is not valid Base64
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy on valid: int(1)
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy on mismatch: throws: Signature validation failed
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 legacy on malformed: throws: SignatureValue is not valid Base64
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy off valid: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy off mismatch: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy off malformed: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy on valid: int(1)
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy on mismatch: throws: Signature validation failed
http://www.w3.org/2000/09/xmldsig#rsa-sha1 legacy on malformed: throws: SignatureValue is not valid Base64
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy off valid: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy off mismatch: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy off malformed: throws: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy on valid: int(1)
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy on mismatch: throws: Signature validation failed
http://www.w3.org/2000/09/xmldsig#hmac-sha1 legacy on malformed: throws: SignatureValue is not valid Base64
