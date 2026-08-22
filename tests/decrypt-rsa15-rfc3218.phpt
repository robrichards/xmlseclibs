--TEST--
RSA-1.5 PKCS#1 v1.5 padding failure uses RFC 3218 random key substitution
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

function expectUniformDecryptFailure($label, callable $fn) {
    try {
        $fn();
        echo "$label: unexpected success\n";
    } catch (Exception $e) {
        $ok = (get_class($e) === 'Exception'
            && $e->getMessage() === XMLSecurityKey::DECRYPTION_FAILURE);
        echo "$label: ".($ok ? "uniform" : (get_class($e)." | ".$e->getMessage()))."\n";
    }
}

/*
 * Ciphertext integer >= modulus: rejected as invalid padding. RFC 3218
 * substitutes random session-key bytes instead of surfacing a padding error.
 */
$rsa15 = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
$rsa15->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$bad = str_repeat("\xff", 256);
$k1 = $rsa15->decryptData($bad);
$k2 = $rsa15->decryptData($bad);
echo "RSA15_LEN: ".(strlen($k1) === XMLSecurityKey::RSA15_SESSION_KEY_SIZE ? "ok" : "bad")."\n";
echo "RSA15_RANDOM: ".($k1 !== $k2 ? "yes" : "no")."\n";

/* Valid RSA-1.5 key transport round-trip still works. */
$pub = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'public'));
$pub->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
$priv = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
$priv->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$session = str_repeat('s', XMLSecurityKey::RSA15_SESSION_KEY_SIZE);
$wrapped = $pub->encryptData($session);
$unwrapped = $priv->decryptData($wrapped);
echo "ROUNDTRIP: ".($unwrapped === $session ? "ok" : "fail")."\n";

/*
 * Full chain: tampered EncryptedKey ciphertext yields a substituted session key,
 * then symmetric decryption fails with the same generic error as a wrong key.
 */
$dom = new DOMDocument();
$dom->load(dirname(__FILE__) . '/basic-doc.xml');
$symKey = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$symKey->generateSessionKey();
$sitePub = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'public'));
$sitePub->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
$enc = new XMLSecEnc();
$enc->allowRSA15KeyTransport = true;
$enc->setNode($dom->documentElement);
$enc->encryptKey($sitePub, $symKey);
$enc->type = XMLSecEnc::Element;
$enc->encryptNode($symKey);

$xpath = new DOMXPath($dom);
$xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
$cv = $xpath->query('//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue')->item(0);
$ct = base64_decode((string) $cv->textContent);
$ct[0] = chr(ord($ct[0]) ^ 0xff);
$cv->textContent = base64_encode($ct);

expectUniformDecryptFailure('CHAIN_PAD', function () use ($dom) {
    $objenc = new XMLSecEnc();
    $objenc->allowRSA15KeyTransport = true;
    $encData = $objenc->locateEncryptedData($dom);
    $objenc->setNode($encData);
    $objenc->type = $encData->getAttribute('Type');
    if (! $objKey = $objenc->locateKey()) {
        throw new Exception('Cannot locate data encryption key');
    }
    $key = null;
    if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
        if ($objKeyInfo->isEncrypted) {
            $objencKey = $objKeyInfo->encryptedCtx;
            $objKeyInfo->loadKey(dirname(__FILE__) . '/privkey.pem', true);
            $key = $objencKey->decryptKey($objKeyInfo);
        }
    }
    if (empty($objKey->key) && ! empty($key)) {
        $objKey->loadKey($key);
    }
    $objenc->decryptNode($objKey, true);
});
?>
--EXPECTF--
RSA15_LEN: ok
RSA15_RANDOM: yes
ROUNDTRIP: ok
CHAIN_PAD: uniform
