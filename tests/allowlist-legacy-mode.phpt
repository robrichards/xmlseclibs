--TEST--
enableLegacyMode() keeps working with non-nullable algorithm allowlists
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
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

function verifyKey($sigAlg) {
    $key = new XMLSecurityKey($sigAlg, array('type' => 'public'));
    $key->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $key;
}

function sigResult($xml, $sigAlg, $legacy, $path) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    try {
        if ($path === 'verifyDocument') {
            return count($dsig->verifyDocument(verifyKey($sigAlg), $doc)) > 0 ? 'OK' : 'FAIL';
        }
        $dsig->locateSignature($doc);
        $dsig->canonicalizeSignedInfo();
        if ($path === 'validateDigest') {
            $ref = $dsig->sigNode->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Reference')->item(0);
            $dsig->validateDigest($ref, 'data'); /* policy check only; the digest value itself does not match */
            return 'OK';
        }
        if ($path === 'validateReference') {
            $dsig->validateReference();
            return 'OK';
        }
        return $dsig->verify(verifyKey($sigAlg)) === 1 ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

$rsaSha1 = signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256);
$digSha1 = signDoc(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1);
$allSha1 = signDoc(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA1);

/* Signature side: legacy off rejects SHA-1, legacy on accepts it on every path. */
foreach (array('verify', 'verifyDocument') as $path) {
    foreach (array(0 => 'OFF', 1 => 'ON') as $legacy => $label) {
        echo "SIG RSA-SHA1 $path $label: ".sigResult($rsaSha1, XMLSecurityKey::RSA_SHA1, (bool) $legacy, $path)."\n";
    }
}
foreach (array('validateDigest', 'validateReference', 'verifyDocument') as $path) {
    foreach (array(0 => 'OFF', 1 => 'ON') as $legacy => $label) {
        echo "DIGEST SHA1 $path $label: ".sigResult($digSha1, XMLSecurityKey::RSA_SHA256, (bool) $legacy, $path)."\n";
    }
}
echo 'BOTH SHA1 verifyDocument ON: '.sigResult($allSha1, XMLSecurityKey::RSA_SHA1, true, 'verifyDocument')."\n";

/* Legacy plus an explicit narrower or custom list: the custom entries stay, the legacy ones are added once. */
$d = new XMLSecurityDSig();
$d->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA512);
$d->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA512);
$d->enableLegacyMode()->enableLegacyMode();
echo 'CUSTOM+LEGACY SIG: '.($d->allowedSignatureAlgorithms === array(
    XMLSecurityKey::RSA_SHA512, XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1) ? 'yes' : 'no')."\n";
echo 'CUSTOM+LEGACY DIGEST: '.($d->allowedDigestAlgorithms === array(
    XMLSecurityDSig::SHA512, XMLSecurityDSig::SHA1) ? 'yes' : 'no')."\n";

/* Legacy plus the explicit full lists: unchanged, nothing duplicated. */
$d = new XMLSecurityDSig();
$d->allowedSignatureAlgorithms = XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS;
$d->allowedDigestAlgorithms = XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS;
$d->enableLegacyMode();
echo 'FULL+LEGACY: '.($d->allowedSignatureAlgorithms === XMLSecurityDSig::SUPPORTED_SIGNATURE_ALGORITHMS
    && $d->allowedDigestAlgorithms === XMLSecurityDSig::SUPPORTED_DIGEST_ALGORITHMS ? 'unchanged' : 'changed')."\n";

/* Legacy plus an empty list: legacy entries are added back. */
$d = new XMLSecurityDSig();
$d->allowedSignatureAlgorithms = array();
$d->allowedDigestAlgorithms = array();
$d->enableLegacyMode();
echo 'EMPTY+LEGACY: '.($d->allowedSignatureAlgorithms === XMLSecurityDSig::LEGACY_SIGNATURE_ALGORITHMS
    && $d->allowedDigestAlgorithms === XMLSecurityDSig::LEGACY_DIGEST_ALGORITHMS ? 'legacy only' : 'other')."\n";

/* The non-algorithm legacy switches are still set. */
$d = new XMLSecurityDSig();
$d->enableLegacyMode();
echo 'LEGACY FLAGS: '.($d->forbidDoctype === false && $d->allowXPathTransforms === true ? 'set' : 'unset')."\n";

/* Decryption side. */
function encryptedDocument($transport, $dataAlg) {
    $public = new XMLSecurityKey($transport, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $symmetric = new XMLSecurityKey($dataAlg);
    $symmetric->generateSessionKey();
    $enc->encryptKey($public, $symmetric);
    $enc->encryptNode($symmetric);
    return $doc;
}

function decrypt(DOMDocument $doc, $legacy) {
    $dec = new XMLSecEnc();
    if ($legacy) {
        $dec->enableLegacyMode();
    }
    try {
        $dec->setNode($dec->locateEncryptedData($doc));
        $dec->type = XMLSecEnc::Element;
        $dataKey = $dec->locateKey();
        $transport = $dec->locateKeyInfo($dataKey);
        $transport->loadKey(__DIR__ . '/privkey.pem', true);
        $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
        $dec->decryptNode($dataKey, true);
        return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

$cases = array(
    'CBC256 + OAEP' => array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES256_CBC),
    '3DES + OAEP' => array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::TRIPLEDES_CBC),
    'GCM256 + RSA-1.5' => array(XMLSecurityKey::RSA_1_5, XMLSecurityKey::AES256_GCM),
    'CBC128 + RSA-1.5' => array(XMLSecurityKey::RSA_1_5, XMLSecurityKey::AES128_CBC),
    'GCM256 + OAEP' => array(XMLSecurityKey::RSA_OAEP, XMLSecurityKey::AES256_GCM),
);
foreach ($cases as $label => $case) {
    foreach (array(0 => 'OFF', 1 => 'ON') as $legacy => $state) {
        echo "DECRYPT $label legacy $state: ".decrypt(encryptedDocument($case[0], $case[1]), (bool) $legacy)."\n";
    }
}

$e = new XMLSecEnc();
$e->enableLegacyMode()->enableLegacyMode();
echo 'ENC LEGACY KEY LIST: '.($e->allowedKeyAlgorithms === array(
    XMLSecurityKey::RSA_OAEP, XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_1_5) ? 'yes' : 'no')."\n";
echo 'ENC LEGACY DATA LIST: '.($e->allowedDataAlgorithms === XMLSecEnc::SUPPORTED_DATA_ALGORITHMS ? 'yes' : 'no')."\n";
echo 'ENC LEGACY RSA15 FLAG: '.($e->allowRSA15KeyTransport === true ? 'yes' : 'no')."\n";

$e = new XMLSecEnc();
$e->allowedKeyAlgorithms = XMLSecEnc::SUPPORTED_KEY_ALGORITHMS;
$e->allowedDataAlgorithms = XMLSecEnc::SUPPORTED_DATA_ALGORITHMS;
$e->enableLegacyMode();
echo 'ENC FULL+LEGACY: '.($e->allowedKeyAlgorithms === XMLSecEnc::SUPPORTED_KEY_ALGORITHMS
    && $e->allowedDataAlgorithms === XMLSecEnc::SUPPORTED_DATA_ALGORITHMS ? 'unchanged' : 'changed')."\n";
?>
--EXPECTF--
SIG RSA-SHA1 verify OFF: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
SIG RSA-SHA1 verify ON: OK
SIG RSA-SHA1 verifyDocument OFF: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
SIG RSA-SHA1 verifyDocument ON: OK
DIGEST SHA1 validateDigest OFF: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
DIGEST SHA1 validateDigest ON: OK
DIGEST SHA1 validateReference OFF: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
DIGEST SHA1 validateReference ON: OK
DIGEST SHA1 verifyDocument OFF: DigestMethod algorithm is not allowed: 'http://www.w3.org/2000/09/xmldsig#sha1'
DIGEST SHA1 verifyDocument ON: OK
BOTH SHA1 verifyDocument ON: OK
CUSTOM+LEGACY SIG: yes
CUSTOM+LEGACY DIGEST: yes
FULL+LEGACY: unchanged
EMPTY+LEGACY: legacy only
LEGACY FLAGS: set
DECRYPT CBC256 + OAEP legacy OFF: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
DECRYPT CBC256 + OAEP legacy ON: OK
DECRYPT 3DES + OAEP legacy OFF: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
DECRYPT 3DES + OAEP legacy ON: OK
DECRYPT GCM256 + RSA-1.5 legacy OFF: RSA-1.5 key transport is disabled (Bleichenbacher risk); set allowRSA15KeyTransport = true to opt in
DECRYPT GCM256 + RSA-1.5 legacy ON: OK
DECRYPT CBC128 + RSA-1.5 legacy OFF: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
DECRYPT CBC128 + RSA-1.5 legacy ON: OK
DECRYPT GCM256 + OAEP legacy OFF: OK
DECRYPT GCM256 + OAEP legacy ON: OK
ENC LEGACY KEY LIST: yes
ENC LEGACY DATA LIST: yes
ENC LEGACY RSA15 FLAG: yes
ENC FULL+LEGACY: unchanged
