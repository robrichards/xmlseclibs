--TEST--
Symmetric loadKey() keeps the previous key when input is rejected, and a too-short key is rejected
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityKey;

function attempt($label, $operation)
{
    try {
        $operation();
        echo "$label: not rejected\n";
    } catch (Exception $e) {
        echo "$label: ".$e->getMessage()."\n";
    }
}

function roundTrip($key, $plain)
{
    $cipher = $key->encryptData($plain);
    return is_string($cipher) && $key->decryptData($cipher) === $plain;
}

$plain = 'payload-bytes';
$pem = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";

/* A fresh object stays unset when PEM text or a too-short key is rejected. */
$fresh = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
attempt('FRESH_PEM', function () use ($fresh, $pem) {
    $fresh->loadKey($pem);
});
echo 'FRESH_PEM_KEY: '.($fresh->key === null ? 'unset' : 'set')."\n";
attempt('FRESH_SHORT', function () use ($fresh) {
    $fresh->loadKey(str_repeat("\x01", 31));
});
echo 'FRESH_SHORT_KEY: '.($fresh->key === null ? 'unset' : 'set')."\n";
attempt('FRESH_ENCRYPT', function () use ($fresh, $plain) {
    $fresh->encryptData($plain);
});

/* A rejected load leaves the original key, which still encrypts and decrypts. */
$original = random_bytes(32);
$key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$key->loadKey($original);
attempt('KEEP_PEM', function () use ($key) {
    $key->loadKey(file_get_contents(dirname(__FILE__) . '/mycert.pem'));
});
echo 'KEEP_PEM_SAME: '.($key->key === $original ? 'yes' : 'no')."\n";
echo 'KEEP_PEM_ROUNDTRIP: '.(roundTrip($key, $plain) ? 'yes' : 'no')."\n";
attempt('KEEP_SHORT', function () use ($key) {
    $key->loadKey(str_repeat("\x02", 8));
});
echo 'KEEP_SHORT_SAME: '.($key->key === $original ? 'yes' : 'no')."\n";
$ciphertext = $key->encryptData($plain);
$other = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$other->loadKey($original);
echo 'KEEP_SHORT_DECRYPT: '.($other->decryptData($ciphertext) === $plain ? 'yes' : 'no')."\n";
attempt('KEEP_FILE', function () use ($key) {
    $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
});
echo 'KEEP_FILE_SAME: '.($key->key === $original ? 'yes' : 'no')."\n";
attempt('KEEP_CERT', function () use ($key) {
    $key->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
});
echo 'KEEP_CERT_SAME: '.($key->key === $original ? 'yes' : 'no')."\n";

/* Cipher setup rejects a too-short key and still accepts an exact or longer key. */
$cases = array(
    'AES256_GCM' => array(XMLSecurityKey::AES256_GCM, 32),
    'AES128_CBC' => array(XMLSecurityKey::AES128_CBC, 16),
);
foreach ($cases as $label => $case) {
    list($algorithm, $size) = $case;
    $short = new XMLSecurityKey($algorithm);
    $short->key = random_bytes($size - 1);
    attempt('SHORT_'.$label, function () use ($short, $plain) {
        $short->encryptData($plain);
    });
    attempt('SHORT_DEC_'.$label, function () use ($short) {
        $short->decryptData(str_repeat('x', 64));
    });

    $exact = new XMLSecurityKey($algorithm);
    $exact->loadKey(random_bytes($size));
    echo 'EXACT_'.$label.': '.(roundTrip($exact, $plain) ? 'yes' : 'no')."\n";

    $longBytes = random_bytes($size + 16);
    $long = new XMLSecurityKey($algorithm);
    $long->loadKey($longBytes);
    $prefix = new XMLSecurityKey($algorithm);
    $prefix->loadKey(substr($longBytes, 0, $size));
    $longCipher = $long->encryptData($plain);
    echo 'OVERLONG_'.$label.': '.($prefix->decryptData($longCipher) === $plain ? 'yes' : 'no')."\n";
}
?>
--EXPECTF--
FRESH_PEM: Asymmetric key material cannot be used as a symmetric key
FRESH_PEM_KEY: unset
FRESH_SHORT: Failure decrypting Data
FRESH_SHORT_KEY: unset
FRESH_ENCRYPT: Key is not loaded
KEEP_PEM: Asymmetric key material cannot be used as a symmetric key
KEEP_PEM_SAME: yes
KEEP_PEM_ROUNDTRIP: yes
KEEP_SHORT: Failure decrypting Data
KEEP_SHORT_SAME: yes
KEEP_SHORT_DECRYPT: yes
KEEP_FILE: Asymmetric key material cannot be used as a symmetric key
KEEP_FILE_SAME: yes
KEEP_CERT: An X.509 certificate cannot be used as a symmetric key
KEEP_CERT_SAME: yes
SHORT_AES256_GCM: Symmetric key is shorter than the 32 bytes required for type "http://www.w3.org/2009/xmlenc11#aes256-gcm".
SHORT_DEC_AES256_GCM: Failure decrypting Data
EXACT_AES256_GCM: yes
OVERLONG_AES256_GCM: yes
SHORT_AES128_CBC: Symmetric key is shorter than the 16 bytes required for type "http://www.w3.org/2001/04/xmlenc#aes128-cbc".
SHORT_DEC_AES128_CBC: Failure decrypting Data
EXACT_AES128_CBC: yes
OVERLONG_AES128_CBC: yes
