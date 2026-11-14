--TEST--
RSA-OAEP XML parameters interoperate with independently configured phpseclib and AES-GCM
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\RSA;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function check($condition, $message) {
    if (! $condition) {
        throw new Exception($message);
    }
}

function digestElement($hash) {
    $uris = array(
        'sha1' => XMLSecurityDSig::SHA1,
        'sha224' => 'http://www.w3.org/2001/04/xmldsig-more#sha224',
        'sha256' => XMLSecurityDSig::SHA256,
        'sha384' => XMLSecurityDSig::SHA384,
        'sha512' => XMLSecurityDSig::SHA512,
    );
    return '<ds:DigestMethod Algorithm="'.$uris[$hash].'"/>';
}

function mgfElement($hash) {
    return '<e11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1'.$hash.'"/>';
}

$private = RSA::createKey(2048);
$public = $private->getPublicKey();
$session = random_bytes(16);
$plaintext = '<Assertion xmlns="urn:synthetic"><Subject>test</Subject></Assertion>';
$label = "\x00label\xff";
$labelXML = '<e:OAEPparams> '.chunk_split(base64_encode($label), 4, "\n").'</e:OAEPparams>';
$cases = array(
    array('explicit SHA1', XMLSecurityKey::RSA_OAEP, 'sha1', 'sha1', '', digestElement('sha1').mgfElement('sha1')),
    array('explicit SHA256', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha256', '', digestElement('sha256').mgfElement('sha256')),
    array('mixed hashes', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha1', '', digestElement('sha256').mgfElement('sha1')),
    array('defaults', XMLSecurityKey::RSA_OAEP, 'sha1', 'sha1', '', '<!-- optional parameters omitted -->'),
    array('default digest', XMLSecurityKey::RSA_OAEP, 'sha1', 'sha256', '', mgfElement('sha256')),
    array('default MGF', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha1', '', digestElement('sha256')),
    array('old defaults', XMLSecurityKey::RSA_OAEP_MGF1P, 'sha1', 'sha1', '', ''),
    array('old SHA256 digest', XMLSecurityKey::RSA_OAEP_MGF1P, 'sha256', 'sha1', '', digestElement('sha256')),
    array('label', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha256', $label, $labelXML.digestElement('sha256').mgfElement('sha256')),
    array('old label', XMLSecurityKey::RSA_OAEP_MGF1P, 'sha1', 'sha1', $label, $labelXML),
    array('empty label', XMLSecurityKey::RSA_OAEP, 'sha1', 'sha1', '', '<e:OAEPparams/>'),
    array('SHA224 SHA384', XMLSecurityKey::RSA_OAEP, 'sha224', 'sha384', '', digestElement('sha224').mgfElement('sha384')),
    array('SHA384 SHA512', XMLSecurityKey::RSA_OAEP, 'sha384', 'sha512', '', digestElement('sha384').mgfElement('sha512')),
    array('SHA512 SHA224', XMLSecurityKey::RSA_OAEP, 'sha512', 'sha224', '', digestElement('sha512').mgfElement('sha224')),
);

foreach ($cases as [$name, $algorithm, $hash, $mgfHash, $oaepLabel, $parameters]) {
    $wrapped = $public->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash($hash)->withMGFHash($mgfHash)->withLabel($oaepLabel)->encrypt($session);
    $aes = new AES('gcm');
    $aes->setKey($session);
    $iv = random_bytes(12);
    $aes->setNonce($iv);
    $ciphertext = $aes->encrypt($plaintext);
    $encrypted = base64_encode($iv.$ciphertext.$aes->getTag(16));
    // The data method follows KeyInfo; unrelated methods must not supply OAEP defaults.
    $xml = '<Root xmlns:e="'.XMLSecEnc::XMLENCNS.'" xmlns:e11="'.XMLSecEnc::XMLENC11NS
        .'" xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS.'">'
        .'<ds:Signature><ds:SignedInfo>'.digestElement('sha512').'</ds:SignedInfo></ds:Signature>'
        .'<e:EncryptedKey><e:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP.'">'
        .digestElement('sha512').mgfElement('sha512').'</e:EncryptionMethod></e:EncryptedKey>'
        .'<e:EncryptedData Type="'.XMLSecEnc::Element.'"><ds:KeyInfo><e:EncryptedKey>'
        .'<e:EncryptionMethod Algorithm="'.$algorithm.'">'.$parameters.'</e:EncryptionMethod>'
        .'<e:CipherData><e:CipherValue>'.base64_encode($wrapped).'</e:CipherValue></e:CipherData>'
        .'</e:EncryptedKey></ds:KeyInfo>'
        .'<e:EncryptionMethod Algorithm="'.XMLSecurityKey::AES128_GCM.'"/>'
        .'<e:CipherData><e:CipherValue>'.$encrypted.'</e:CipherValue></e:CipherData>'
        .'</e:EncryptedData></Root>';
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $before = $doc->saveXML();
    $enc = new XMLSecEnc();
    $enc->allowedKeyAlgorithms = XMLSecEnc::DEFAULT_KEY_ALGORITHMS;
    $enc->allowedDataAlgorithms = XMLSecEnc::DEFAULT_DATA_ALGORITHMS;
    $enc->setNode($enc->locateEncryptedData($doc));
    $key = $enc->locateKey();
    check($key->getAlgorithm() === XMLSecurityKey::AES128_GCM, 'Wrong data method');
    $transport = $enc->locateKeyInfo($key);
    $transport->loadKey($private->toString('PKCS8'));
    $key->loadKey($transport->encryptedCtx->decryptKey($transport));
    check($key->key === $session, 'Wrong unwrapped session key');
    check($enc->decryptNode($key, false) === $plaintext, 'AES-GCM decryption failed');
    check($doc->saveXML() === $before, 'Incoming XML was modified');
    echo "$name: OK\n";
}

$outbound = array(
    array('programmatic SHA256', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha256', '', false),
    array('configured SHA1', XMLSecurityKey::RSA_OAEP, 'sha1', 'sha1', '', true),
    array('mixed label', XMLSecurityKey::RSA_OAEP, 'sha256', 'sha1', $label, true),
    array('old programmatic', XMLSecurityKey::RSA_OAEP_MGF1P, 'sha1', 'sha1', '', false),
    array('old configured', XMLSecurityKey::RSA_OAEP_MGF1P, 'sha256', 'sha1', $label, true),
);
foreach ($outbound as [$name, $algorithm, $hash, $mgfHash, $oaepLabel, $configure]) {
    $digestURI = $hash === 'sha1' ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256;
    $mgfURI = XMLSecEnc::XMLENC11NS.'mgf1'.$mgfHash;
    $key = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $key->loadKey($public->toString('PKCS8'));
    if ($configure) {
        $key->setOAEPParameters($digestURI, $mgfURI, $oaepLabel);
    }
    $rawKey = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
    $rawKey->loadKey($session);
    foreach (array(false, true) as $append) {
        $enc = new XMLSecEnc();
        $enc->encryptKey($key, $rawKey, $append);
        if ($append) {
            $source = new DOMDocument();
            $source->loadXML($plaintext);
            $enc->setNode($source->documentElement);
            $enc->type = XMLSecEnc::Element;
            $node = $enc->encryptNode($rawKey, false);
        } else {
            $node = $enc->encKey;
        }
        $doc = new DOMDocument();
        $doc->loadXML($node->ownerDocument->saveXML($node));
        $xp = new DOMXPath($doc);
        $xp->registerNamespace('e', XMLSecEnc::XMLENCNS);
        $xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xp->registerNamespace('e11', XMLSecEnc::XMLENC11NS);
        $method = $xp->query('//e:EncryptedKey/e:EncryptionMethod')->item(0);
        check($method->getAttribute('Algorithm') === $algorithm, 'Wrong outbound algorithm');
        check($xp->evaluate('string(ds:DigestMethod/@Algorithm)', $method) === $digestURI, 'Wrong outbound digest');
        check($xp->evaluate('count(ds:DigestMethod)', $method) === 1.0, 'Duplicate outbound digest');
        $mgfs = $xp->query('e11:MGF', $method);
        check($mgfs->length === ($algorithm === XMLSecurityKey::RSA_OAEP ? 1 : 0), 'Wrong outbound MGF count');
        if ($mgfs->length) {
            check($mgfs->item(0)->getAttribute('Algorithm') === $mgfURI, 'Wrong outbound MGF');
        }
        check($xp->evaluate('string(e:OAEPparams)', $method) === base64_encode($oaepLabel), 'Wrong outbound label');
        $cipher = base64_decode($xp->evaluate('string(//e:EncryptedKey/e:CipherData/e:CipherValue)'), true);
        $decoded = $private->withPadding(RSA::ENCRYPTION_OAEP)
            ->withHash($hash)->withMGFHash($mgfHash)->withLabel($oaepLabel)->decrypt($cipher);
        check($decoded === $session, 'Independent outbound unwrap failed');
    }
    echo "outbound $name: OK\n";
}

// Changing OAEP handling must not change the shared RSA-PSS configuration.
$pss = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256_MGF1, array('type' => 'private'));
$pss->loadKey($private->toString('PKCS8'));
$signature = $pss->signData('PSS regression');
$independentPSS = $public->withPadding(RSA::SIGNATURE_PSS)->withHash('sha256')->withMGFHash('sha256');
check($independentPSS->verify('PSS regression', $signature), 'PSS configuration changed');
echo "RSA-PSS: OK\n";

// A valid ciphertext with incorrect declared parameters must not trigger hash guessing.
$cipher = $public->withPadding(RSA::ENCRYPTION_OAEP)
    ->withHash('sha256')->withMGFHash('sha256')->withLabel($label)->encrypt($session);
foreach (array(
    array('sha1', 'sha256', $label),
    array('sha256', 'sha1', $label),
    array('sha256', 'sha256', ''),
) as [$hash, $mgfHash, $oaepLabel]) {
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP, array('type' => 'private'));
    $key->setOAEPParameters(
        $hash === 'sha1' ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256,
        XMLSecEnc::XMLENC11NS.'mgf1'.$mgfHash,
        $oaepLabel
    );
    $key->loadKey($private->toString('PKCS8'));
    try {
        $key->decryptData($cipher);
        throw new RuntimeException('Unexpected decryption success');
    } catch (Exception $e) {
        check(get_class($e) === 'Exception' && $e->getMessage() === XMLSecurityKey::DECRYPTION_FAILURE, 'Non-uniform failure');
    }
}
echo "wrong digest/MGF/label: uniform\n";

$cipher = $public->withPadding(RSA::ENCRYPTION_OAEP)
    ->withHash('sha256')->withMGFHash('sha256')->withLabel('')->encrypt($session);
$doc = new DOMDocument();
$doc->loadXML('<e:EncryptedKey xmlns:e="'.XMLSecEnc::XMLENCNS.'">'
    .'<e:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP.'"/>'
    .'<e:CipherData><e:CipherValue>'.base64_encode($cipher).'</e:CipherValue></e:CipherData>'
    .'</e:EncryptedKey>');
$key = XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
$key->loadKey($private->toString('PKCS8'));
try {
    $key->encryptedCtx->decryptKey($key);
    throw new RuntimeException('Nonconforming ciphertext was accepted');
} catch (Exception $e) {
    check(get_class($e) === 'Exception' && $e->getMessage() === XMLSecurityKey::DECRYPTION_FAILURE, 'Non-uniform failure');
}
echo "no implicit SHA256 fallback: OK\n";
?>
--EXPECTF--
explicit SHA1: OK
explicit SHA256: OK
mixed hashes: OK
defaults: OK
default digest: OK
default MGF: OK
old defaults: OK
old SHA256 digest: OK
label: OK
old label: OK
empty label: OK
SHA224 SHA384: OK
SHA384 SHA512: OK
SHA512 SHA224: OK
outbound programmatic SHA256: OK
outbound configured SHA1: OK
outbound mixed label: OK
outbound old programmatic: OK
outbound old configured: OK
RSA-PSS: OK
wrong digest/MGF/label: uniform
no implicit SHA256 fallback: OK
