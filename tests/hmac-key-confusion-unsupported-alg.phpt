--TEST--
HMAC key confusion: reject certificates whose public-key algorithm is unsupported
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * This fixture is an X.509 certificate with subjectPublicKeyInfo OID
 * 1.3.101.110 (X25519). phpseclib parses the certificate structure, but
 * PublicKeyLoader throws NoKeyLoadedException because it cannot instantiate
 * that public-key algorithm. The HMAC guard must still reject it.
 */
$certPem = file_get_contents(dirname(__FILE__) . '/x25519-cert.pem');

$x509 = new X509();
if (! is_array($x509->loadX509($certPem))) {
    throw new Exception('fixture must parse as an X.509 certificate');
}
try {
    PublicKeyLoader::load($certPem);
    throw new Exception('fixture must not load as a usable public key');
} catch (NoKeyLoadedException $e) {
    /* expected */
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

$derCert = derFromPem($certPem);
$b64Cert = headerlessBase64($certPem);

tryLoad('LOAD_PEM', $certPem);
tryLoad('LOAD_DER', $derCert);
tryLoad('LOAD_B64', $b64Cert);
tryLoad('LOAD_B64_COMPACT', preg_replace('/\s+/', '', $b64Cert));

tryAssign('ASSIGN_PEM', $certPem);
tryAssign('ASSIGN_DER', $derCert);
tryAssign('ASSIGN_B64', $b64Cert);
?>
--EXPECTF--
LOAD_PEM: Asymmetric key material cannot be used as an HMAC key
LOAD_DER: Asymmetric key material cannot be used as an HMAC key
LOAD_B64: Asymmetric key material cannot be used as an HMAC key
LOAD_B64_COMPACT: Asymmetric key material cannot be used as an HMAC key
ASSIGN_PEM_VERIFY: -1
ASSIGN_PEM_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_DER_VERIFY: -1
ASSIGN_DER_SIGN: Asymmetric key material cannot be used as an HMAC key
ASSIGN_B64_VERIFY: -1
ASSIGN_B64_SIGN: Asymmetric key material cannot be used as an HMAC key
