--TEST--
HMAC key confusion: reject unsupported standalone public keys (SM2, Diffie-Hellman)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * These fixtures are OpenSSL-generated public keys whose algorithms phpseclib
 * does not instantiate. PublicKeyLoader throws NoKeyLoadedException and they
 * are not X.509 certificates. The HMAC guard must still reject them from the
 * PEM armor and from the ASN.1 SubjectPublicKeyInfo structure (DER / bare
 * base64).
 */
function assertUnsupportedStandaloneKey($path)
{
    $pem = file_get_contents($path);
    try {
        PublicKeyLoader::load($pem);
        throw new Exception($path.' must not load as a usable public key');
    } catch (NoKeyLoadedException $e) {
        /* expected */
    }
    $x509 = new X509();
    if (is_array($x509->loadX509($pem))) {
        throw new Exception($path.' must not parse as an X.509 certificate');
    }
    return $pem;
}

function headerlessBase64($pem)
{
    $body = preg_replace('/-----BEGIN [^-]+-----/', '', $pem);
    $body = preg_replace('/-----END [^-]+-----/', '', $body);
    return trim($body);
}

function derFromPem($pem)
{
    $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
    if (! is_string($der) || $der === '' || ord($der[0]) !== 0x30) {
        throw new Exception('fixture is not raw DER');
    }
    if (strpos($der, '-----BEGIN') !== false) {
        throw new Exception('DER fixture still has PEM armor');
    }
    return $der;
}

function tryLoad($label, $material)
{
    try {
        $key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
        $key->loadKey($material);
        echo $label.": not rejected\n";
    } catch (Exception $e) {
        echo $label.": ".$e->getMessage()."\n";
    }
}

function tryAssign($label, $material)
{
    $key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
    $key->key = $material;
    echo $label."_VERIFY: ".$key->verifySignature('signed-payload', 'not-a-signature')."\n";
    try {
        $key->signData('signed-payload');
        echo $label."_SIGN: not rejected\n";
    } catch (Exception $e) {
        echo $label."_SIGN: ".$e->getMessage()."\n";
    }
}

foreach (array('SM2' => 'sm2-pub.pem', 'DH' => 'dh-pub.pem') as $name => $file) {
    $pem = assertUnsupportedStandaloneKey(dirname(__FILE__) . '/' . $file);
    $der = derFromPem($pem);
    $b64 = headerlessBase64($pem);

    tryLoad('LOAD_'.$name.'_PEM', $pem);
    tryLoad('LOAD_'.$name.'_DER', $der);
    tryLoad('LOAD_'.$name.'_B64', $b64);
    tryLoad('LOAD_'.$name.'_B64_COMPACT', preg_replace('/\s+/', '', $b64));

    tryAssign('ASSIGN_'.$name.'_PEM', $pem);
    tryAssign('ASSIGN_'.$name.'_DER', $der);
    tryAssign('ASSIGN_'.$name.'_B64', $b64);
}
?>
--EXPECTF--
LOAD_SM2_PEM: Asymmetric key material cannot be used as an HMAC key
LOAD_SM2_DER: Asymmetric key material cannot be used as an HMAC key
LOAD_SM2_B64: Asymmetric key material cannot be used as an HMAC key
LOAD_SM2_B64_COMPACT: Asymmetric key material cannot be used as an HMAC key
ASSIGN_SM2_PEM_VERIFY: -1
ASSIGN_SM2_PEM_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_SM2_DER_VERIFY: -1
ASSIGN_SM2_DER_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_SM2_B64_VERIFY: -1
ASSIGN_SM2_B64_SIGN: Asymmetric key material cannot be used as an HMAC key
LOAD_DH_PEM: Asymmetric key material cannot be used as an HMAC key
LOAD_DH_DER: Asymmetric key material cannot be used as an HMAC key
LOAD_DH_B64: Asymmetric key material cannot be used as an HMAC key
LOAD_DH_B64_COMPACT: Asymmetric key material cannot be used as an HMAC key
ASSIGN_DH_PEM_VERIFY: -1
ASSIGN_DH_PEM_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_DH_DER_VERIFY: -1
ASSIGN_DH_DER_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_DH_B64_VERIFY: -1
ASSIGN_DH_B64_SIGN: Asymmetric key material cannot be used as an HMAC key
