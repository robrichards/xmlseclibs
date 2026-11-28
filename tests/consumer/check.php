<?php
/**
 * Run by tests/consumer/run.sh inside a throw-away Composer project that has
 * installed this package as a dependency.
 *
 * Usage: php check.php <autoload|direct|direct-after-autoload> [legacy]
 */

use phpseclib3\Crypt\RSA;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

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

printf(
    "%s %s alg=%s verify=%d references=%s modified_content_rejected=%s\n",
    $mode,
    $legacy ? 'legacy' : 'default',
    $legacy ? 'rsa-sha1' : 'rsa-sha256',
    $result,
    $refs ? 'ok' : 'fail',
    $modifiedRejected ? 'yes' : 'no'
);
exit($result === 1 && $refs && $modifiedRejected ? 0 : 1);
