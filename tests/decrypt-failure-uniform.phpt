--TEST--
Decrypt failures always surface a single Exception / message (no oracle)
--FILE--
<?php
/*
 * PHPUnit runs PHPT jobs with display_errors=1 and redirects STDERR to STDOUT.
 * OpenSSL may write padding/decoding diagnostics to STDERR on some platforms
 * (notably Linux CI). Silence PHP display noise and use %A in EXPECTF so any
 * interleaved STDERR text does not fail the oracle assertions.
 */
error_reporting(0);
ini_set('display_errors', '0');

require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Assert a decrypt failure is exactly Exception("Failure decrypting Data").
 * Distinct exception classes/messages would form a ciphertext-validity oracle.
 */
function expectDecryptFailure($label, $key, $data) {
    try {
        $key->decryptData($data);
        echo "$label: unexpected success\n";
    } catch (Exception $e) {
        $ok = (get_class($e) === 'Exception'
            && $e->getMessage() === XMLSecurityKey::DECRYPTION_FAILURE);
        echo "$label: ".($ok ? "uniform" : (get_class($e)." | ".$e->getMessage()))."\n";
    } catch (Throwable $e) {
        echo "$label: ".get_class($e)." | ".$e->getMessage()."\n";
    }
}

$aesKey = str_repeat('k', 16);
$iv = str_repeat('i', 16);

/* CBC: ciphertext length not a multiple of the block size (phpseclib LengthException). */
$cbc = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
$cbc->key = $aesKey;
expectDecryptFailure('CBC_LEN', $cbc, $iv.'abc');

/* CBC: block-aligned garbage (bad padding). */
expectDecryptFailure('CBC_PAD', $cbc, $iv.str_repeat('x', 16));

/* CBC: IV only / empty ciphertext. */
expectDecryptFailure('CBC_EMPTY', $cbc, $iv);

/* GCM: wrong auth tag (phpseclib BadDecryptionException). */
$gcm = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
$gcm->key = $aesKey;
$nonce = str_repeat('n', 12);
expectDecryptFailure('GCM_TAG', $gcm, $nonce.'ciphertexthere!!'.str_repeat('t', 16));

/* RSA-OAEP unwrap: wrong ciphertext / wrong length (RuntimeException / LengthException). */
$oaep = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
$oaep->loadKey(dirname(__FILE__) . '/privkey.pem', true);
expectDecryptFailure('RSA_OAEP_BAD', $oaep, str_repeat('A', 256));
expectDecryptFailure('RSA_OAEP_SHORT', $oaep, 'short');

/* RSA-1.5 unwrap: wrong ciphertext (RuntimeException). */
$rsa15 = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
$rsa15->loadKey(dirname(__FILE__) . '/privkey.pem', true);
expectDecryptFailure('RSA15_BAD', $rsa15, str_repeat('B', 256));

/* Successful round-trip still works (control). */
$ok = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
$ok->generateSessionKey();
$ct = $ok->encryptData('hello');
$pt = $ok->decryptData($ct);
echo "ROUNDTRIP: ".($pt === 'hello' ? 'ok' : 'fail')."\n";
?>
--EXPECTF--
CBC_LEN: uniform%A
CBC_PAD: uniform%A
CBC_EMPTY: uniform%A
GCM_TAG: uniform%A
RSA_OAEP_BAD: uniform%A
RSA_OAEP_SHORT: uniform%A
RSA15_BAD: uniform%A
ROUNDTRIP: ok
