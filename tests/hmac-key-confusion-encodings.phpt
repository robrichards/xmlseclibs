--TEST--
HMAC key confusion: reject DER and headerless base64 asymmetric material
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * PEM body with the armor lines removed (newlines kept). This is the form
 * the previous -----BEGIN check did not recognize.
 */
function headerlessBase64($pem)
{
    $body = preg_replace('/-----BEGIN [^-]+-----/', '', $pem);
    $body = preg_replace('/-----END [^-]+-----/', '', $body);
    $body = trim($body);
    if ($body === '' || strpos($body, '-----BEGIN') !== false) {
        throw new Exception('fixture still has PEM armor');
    }
    return $body;
}

function derFromPem($pem)
{
    $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
    if (! is_string($der) || $der === '' || strpos($der, '-----BEGIN') !== false) {
        throw new Exception('fixture is not raw DER');
    }
    if (ord($der[0]) !== 0x30) {
        throw new Exception('fixture DER is not an ASN.1 SEQUENCE');
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

$certPem = file_get_contents(dirname(__FILE__) . '/mycert.pem');
$x509 = new X509();
if (! is_array($x509->loadX509($certPem))) {
    throw new Exception('unable to load test certificate');
}
$pubPem = $x509->getPublicKey()->toString('PKCS8');

$derCert = derFromPem($certPem);
$derPub = derFromPem($pubPem);
$b64Cert = headerlessBase64($certPem);
$b64Pub = headerlessBase64($pubPem);

tryLoad('LOAD_DER_CERT', $derCert);
tryLoad('LOAD_DER_PUB', $derPub);
tryLoad('LOAD_B64_CERT', $b64Cert);
tryLoad('LOAD_B64_PUB', $b64Pub);
tryLoad('LOAD_B64_CERT_COMPACT', preg_replace('/\s+/', '', $b64Cert));
tryLoad('LOAD_B64_PUB_COMPACT', preg_replace('/\s+/', '', $b64Pub));

/* Password-protected PKCS#8 does not parse as a key without the passphrase. */
$priv = PublicKeyLoader::load(file_get_contents(dirname(__FILE__) . '/privkey.pem'));
tryLoad('LOAD_ENC_PKCS8', $priv->withPassword('secret')->toString('PKCS8'));

/* Direct assignment bypasses loadKey(); verify/sign must still refuse. */
$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->key = $derPub;
echo "VERIFY_DER_PUB: ".$key->verifySignature('signed-payload', 'not-a-signature')."\n";
try {
    $key->signData('signed-payload');
    echo "SIGN_DER_PUB: not rejected\n";
} catch (Exception $e) {
    echo "SIGN_DER_PUB: ".$e->getMessage()."\n";
}

$data = 'signed-payload';

$binary = "\x00\x01\xff\x30\x82 binary-hmac-secret \x80\x7f";
$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->loadKey($binary);
$sig = $key->signData($data);
echo "HMAC_BIN: ".($key->verifySignature($data, $sig) === 1 ? "yes" : "no")."\n";

$b64Secret = base64_encode(hex2bin('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'));
$key = new XMLSecurityKey(XMLSecurityKey::HMAC_SHA1);
$key->loadKey($b64Secret);
$sig = $key->signData($data);
echo "HMAC_B64: ".($key->verifySignature($data, $sig) === 1 ? "yes" : "no")."\n";
?>
--EXPECTF--
LOAD_DER_CERT: Asymmetric key material cannot be used as an HMAC key
LOAD_DER_PUB: Asymmetric key material cannot be used as an HMAC key
LOAD_B64_CERT: Asymmetric key material cannot be used as an HMAC key
LOAD_B64_PUB: Asymmetric key material cannot be used as an HMAC key
LOAD_B64_CERT_COMPACT: Asymmetric key material cannot be used as an HMAC key
LOAD_B64_PUB_COMPACT: Asymmetric key material cannot be used as an HMAC key
LOAD_ENC_PKCS8: Asymmetric key material cannot be used as an HMAC key
VERIFY_DER_PUB: -1
SIGN_DER_PUB: Asymmetric key material cannot be used as an HMAC key
HMAC_BIN: yes
HMAC_B64: yes
