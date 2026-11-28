<?php
/**
 * Run by tests/consumer/run.sh inside a throw-away Composer project that has
 * installed this package as a dependency.
 *
 * Usage: php check.php <autoload|direct|direct-after-autoload|direct-phpseclib-only> [legacy]
 */

use phpseclib3\Crypt\RSA;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$mode = $argv[1] ?? 'autoload';
$legacy = ($argv[2] ?? '') === 'legacy';
$package = __DIR__ . '/vendor/robrichards/xmlseclibs/xmlseclibs.php';

switch ($mode) {
    case 'autoload':
        require __DIR__ . '/vendor/autoload.php';
        break;
    case 'direct':
        // Only the package file is included; the consumer loads no autoloader itself.
        require $package;
        break;
    case 'direct-after-autoload':
        require __DIR__ . '/vendor/autoload.php';
        class_exists(XMLSecurityDSig::class);
        require $package;
        break;
    case 'direct-phpseclib-only':
        // The application loads phpseclib through its own autoloader, which has no
        // mapping for xmlseclibs, and then includes the package file directly.
        $vendor = __DIR__ . '/vendor';
        spl_autoload_register(static function (string $class) use ($vendor): void {
            $maps = [
                'phpseclib3\\' => $vendor . '/phpseclib/phpseclib/phpseclib/',
                'ParagonIE\\ConstantTime\\' => $vendor . '/paragonie/constant_time_encoding/src/',
            ];
            foreach ($maps as $prefix => $dir) {
                if (strncmp($class, $prefix, strlen($prefix)) === 0) {
                    $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
                    if (is_file($file)) {
                        require $file;
                    }
                    return;
                }
            }
        });
        require $vendor . '/phpseclib/phpseclib/phpseclib/bootstrap.php';
        if (class_exists('RobRichards\\XMLSecLibs\\Internal\\KeyTransportAlgorithms')) {
            fwrite(STDERR, "setup error: xmlseclibs is already resolvable\n");
            exit(2);
        }
        require $package;
        break;
    default:
        fwrite(STDERR, "unknown mode: $mode\n");
        exit(2);
}

$alg = $legacy ? XMLSecurityKey::RSA_SHA1 : XMLSecurityKey::RSA_SHA256;
$digest = $legacy ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256;

$private = RSA::createKey(2048);
$privatePem = $private->toString('PKCS8');
$publicPem = $private->getPublicKey()->toString('PKCS8');

$doc = new DOMDocument();
$doc->loadXML('<Root><Item>hello</Item></Root>');

$dsig = new XMLSecurityDSig();
$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$dsig->addReference(
    $doc,
    $digest,
    ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
    ['force_uri' => true]
);
$key = new XMLSecurityKey($alg, ['type' => 'private']);
$key->loadKey($privatePem);
$dsig->sign($key);
$dsig->appendSignature($doc->documentElement);
$xml = $doc->saveXML();

$verify = static function (string $xml) use ($legacy, $alg, $publicPem): array {
    $d = new DOMDocument();
    $d->loadXML($xml);
    $v = new XMLSecurityDSig();
    if ($legacy) {
        $v->enableLegacyMode();
    }
    if (!$v->locateSignature($d)) {
        throw new RuntimeException('signature not found');
    }
    $v->canonicalizeSignedInfo();
    $k = new XMLSecurityKey($alg, ['type' => 'public']);
    $k->loadKey($publicPem);
    return [$v->verify($k), $v->validateReference()];
};

[$result, $refs] = $verify($xml);
$modifiedRejected = false;
try {
    $verify(str_replace('hello', 'changed', $xml));
} catch (Exception $e) {
    $modifiedRejected = true;
}

// Key transport round trip: wrap a data key for an RSA key, then unwrap it and decrypt.
$transportAlg = $legacy ? XMLSecurityKey::RSA_1_5 : XMLSecurityKey::RSA_OAEP;
$encDoc = new DOMDocument();
$encDoc->loadXML('<Root>payload</Root>');
$enc = new XMLSecEnc();
$enc->setNode($encDoc->documentElement);
$enc->type = XMLSecEnc::Element;
$session = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$session->generateSessionKey();
$wrap = new XMLSecurityKey($transportAlg, ['type' => 'public']);
$wrap->loadKey($publicPem);
$enc->encryptKey($wrap, $session);
$enc->encryptNode($session);

$dec = new XMLSecEnc();
if ($legacy) {
    $dec->enableLegacyMode();
}
$dec->setNode($dec->locateEncryptedData($encDoc));
$dec->type = XMLSecEnc::Element;
$dataKey = $dec->locateKey();
$unwrap = $dec->locateKeyInfo($dataKey);
$unwrap->loadKey($privatePem);
$dataKey->loadKey($unwrap->encryptedCtx->decryptKey($unwrap));
$dec->decryptNode($dataKey, true);
$transportOk = $encDoc->documentElement->textContent === 'payload';

printf(
    "%s %s alg=%s verify=%d references=%s modified_content_rejected=%s key_transport=%s\n",
    $mode,
    $legacy ? 'legacy' : 'default',
    $legacy ? 'rsa-sha1' : 'rsa-sha256',
    $result,
    $refs ? 'ok' : 'fail',
    $modifiedRejected ? 'yes' : 'no',
    $transportOk ? ($legacy ? 'rsa-1_5 ok' : 'rsa-oaep ok') : 'fail'
);
exit($result === 1 && $refs && $modifiedRejected && $transportOk ? 0 : 1);
