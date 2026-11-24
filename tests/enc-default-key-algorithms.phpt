--TEST--
XMLSecEnc::$allowedKeyAlgorithms defaults to DEFAULT_KEY_ALGORITHMS (RSA-OAEP only)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const ENC_NS = 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

/* Encrypt '<root>payload</root>' with AES-256-GCM, wrapping the session key with $transport. */
function encryptedDocument($transport) {
    $public = new XMLSecurityKey($transport, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $symmetric = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $symmetric->generateSessionKey();
    $enc->encryptKey($public, $symmetric);
    $enc->encryptNode($symmetric);
    return $doc;
}

/* Decrypt with the default policy, optionally adjusted by $configure. */
function decrypt(DOMDocument $doc, ?callable $configure = null) {
    $dec = new XMLSecEnc();
    if ($configure) {
        $configure($dec);
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transport = $dec->locateKeyInfo($dataKey);
    $transport->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
    $dec->decryptNode($dataKey, true);
    return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
}

/* Resolve the key transport only (no crypto) for a hand-written document. */
function resolve($xml, ?callable $configure = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    if ($configure) {
        $configure($dec);
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    return $dec->locateKeyInfo($dec->locateKey())->getAlgorithm();
}

/* 1. Default value. */
$enc = new XMLSecEnc();
echo 'DEFAULT: '.($enc->allowedKeyAlgorithms === XMLSecEnc::DEFAULT_KEY_ALGORITHMS ? 'DEFAULT_KEY_ALGORITHMS' : var_export($enc->allowedKeyAlgorithms, true))."\n";

/* 2. RSA-OAEP variants decrypt with the defaults. */
attempt('OAEP_MGF1P', function () {
    return decrypt(encryptedDocument(XMLSecurityKey::RSA_OAEP_MGF1P));
});
attempt('OAEP', function () {
    return decrypt(encryptedDocument(XMLSecurityKey::RSA_OAEP));
});

/* 3. RSA-OAEP with SHA-1 parameters (implicit defaults and explicit), as sent by e.g. Shibboleth IdP. */
$private = PublicKeyLoader::load(file_get_contents(__DIR__ . '/privkey.pem'));
foreach (array(
    'OAEP_SHA1_IMPLICIT' => '',
    'OAEP_SHA1_EXPLICIT' => '<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'"/>'
        .'<xenc11:MGF xmlns:xenc11="'.XMLSecEnc::XMLENC11NS.'" Algorithm="'.XMLSecEnc::XMLENC11NS.'mgf1sha1"/>',
) as $name => $params) {
    attempt($name, function () use ($private, $params) {
        $session = random_bytes(32);
        $wrapped = $private->getPublicKey()->withPadding(RSA::ENCRYPTION_OAEP)
            ->withHash('sha1')->withMGFHash('sha1')->encrypt($session);
        $aes = new AES('gcm');
        $aes->setKey($session);
        $iv = random_bytes(12);
        $aes->setNonce($iv);
        $ct = $aes->encrypt('<root>payload</root>');
        $xml = '<Root><xenc:EncryptedData '.ENC_NS.' Type="'.XMLSecEnc::Element.'">'
            .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
            .'<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP.'">'.$params.'</xenc:EncryptionMethod>'
            .'<xenc:CipherData><xenc:CipherValue>'.base64_encode($wrapped).'</xenc:CipherValue></xenc:CipherData>'
            .'</xenc:EncryptedKey></ds:KeyInfo>'
            .'<xenc:CipherData><xenc:CipherValue>'.base64_encode($iv.$ct.$aes->getTag(16)).'</xenc:CipherValue></xenc:CipherData>'
            .'</xenc:EncryptedData></Root>';
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $dec = new XMLSecEnc();
        $dec->setNode($dec->locateEncryptedData($doc));
        $dec->type = XMLSecEnc::Element;
        $dataKey = $dec->locateKey();
        $transport = $dec->locateKeyInfo($dataKey);
        $transport->loadKey(__DIR__ . '/privkey.pem', true);
        $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
        $dec->decryptNode($dataKey, true);
        return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
    });
}

/* 4. RSA-1.5 needs the flag AND an allowlist that includes it. */
$rsa15 = encryptedDocument(XMLSecurityKey::RSA_1_5);
attempt('RSA15_DEFAULT', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true));
});
attempt('RSA15_FLAG_ONLY', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->allowRSA15KeyTransport = true;
    });
});
attempt('RSA15_FLAG_AND_LIST', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->allowRSA15KeyTransport = true;
        $dec->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5;
    });
});
attempt('RSA15_LIST_ONLY', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->allowedKeyAlgorithms[] = XMLSecurityKey::RSA_1_5;
    });
});
attempt('RSA15_LEGACY_MODE', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->enableLegacyMode();
    });
});

/* 5. Explicit null opts out of the allowlist (RSA-1.5 still needs its flag;
 *    non-key-transport EncryptedKey algorithms are always rejected). */
attempt('NULL_RSA15_NO_FLAG', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->allowedKeyAlgorithms = null;
    });
});
attempt('NULL_RSA15_FLAG', function () use ($rsa15) {
    return decrypt($rsa15->cloneNode(true), function ($dec) {
        $dec->allowedKeyAlgorithms = null;
        $dec->allowRSA15KeyTransport = true;
    });
});
$nonTransport = '<Root><xenc:EncryptedData '.ENC_NS.'>'
    .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
    .'<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_SHA256.'"/>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></Root>';
attempt('NON_TRANSPORT_DEFAULT', function () use ($nonTransport) {
    return resolve($nonTransport);
});
attempt('NON_TRANSPORT_NULL', function () use ($nonTransport) {
    return resolve($nonTransport, function ($dec) {
        $dec->allowedKeyAlgorithms = null;
    });
});
attempt('LEGACY_NULL_STAYS_NULL', function () {
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = null;
    $dec->enableLegacyMode();
    return var_export($dec->allowedKeyAlgorithms, true);
});

/* 6. The default applies to nested and RetrievalMethod-referenced EncryptedKeys.
 *    (For the nested case the outer key transport is returned once the inner
 *    EncryptedKey has passed the policy.) */
$innerRSA15 = '<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_1_5.'"/>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
$nested = '<Root><xenc:EncryptedData '.ENC_NS.'>'
    .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
    .'<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP_MGF1P.'"/>'
    .'<ds:KeyInfo>'.$innerRSA15.'</ds:KeyInfo>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></Root>';
$retrieval = '<Root '.ENC_NS.'><xenc:EncryptedData>'
    .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
    .'<ds:KeyInfo><ds:RetrievalMethod URI="#ek1" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/></ds:KeyInfo>'
    .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>'
    .str_replace('<xenc:EncryptedKey>', '<xenc:EncryptedKey Id="ek1">', $innerRSA15).'</Root>';
$flagOnly = function ($dec) {
    $dec->allowRSA15KeyTransport = true;
};
$flagAndNull = function ($dec) {
    $dec->allowRSA15KeyTransport = true;
    $dec->allowedKeyAlgorithms = null;
};
attempt('NESTED_DEFAULT', function () use ($nested, $flagOnly) {
    return resolve($nested, $flagOnly);
});
attempt('NESTED_NULL', function () use ($nested, $flagAndNull) {
    return resolve($nested, $flagAndNull);
});
attempt('RETRIEVAL_DEFAULT', function () use ($retrieval, $flagOnly) {
    return resolve($retrieval, $flagOnly);
});
attempt('RETRIEVAL_NULL', function () use ($retrieval, $flagAndNull) {
    return resolve($retrieval, $flagAndNull);
});

/* 7. Static entry points use the same default; explicit null opts out. */
$doc = new DOMDocument();
$doc->loadXML($nested);
$outer = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
$inner = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(1);
attempt('STATIC_FROM_DEFAULT', function () use ($inner) {
    return XMLSecurityKey::fromEncryptedKeyElement($inner, 0, true)->getAlgorithm();
});
attempt('STATIC_FROM_NULL', function () use ($inner) {
    return XMLSecurityKey::fromEncryptedKeyElement($inner, 0, true, null)->getAlgorithm();
});
attempt('STATIC_LOCATE_DEFAULT', function () use ($outer) {
    $base = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
    return XMLSecEnc::staticLocateKeyInfo($base, $outer, 0, true)->getAlgorithm();
});
attempt('STATIC_LOCATE_NULL', function () use ($outer) {
    $base = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
    return XMLSecEnc::staticLocateKeyInfo($base, $outer, 0, true, null)->getAlgorithm();
});
?>
--EXPECTF--
DEFAULT: DEFAULT_KEY_ALGORITHMS
OAEP_MGF1P: OK
OAEP: OK
OAEP_SHA1_IMPLICIT: OK
OAEP_SHA1_EXPLICIT: OK
RSA15_DEFAULT: RSA-1.5 key transport is disabled (Bleichenbacher risk); set allowRSA15KeyTransport = true to opt in
RSA15_FLAG_ONLY: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'; add XMLSecurityKey::RSA_1_5 to allowedKeyAlgorithms (or call enableLegacyMode()) to opt in
RSA15_FLAG_AND_LIST: OK
RSA15_LIST_ONLY: RSA-1.5 key transport is disabled (Bleichenbacher risk); set allowRSA15KeyTransport = true to opt in
RSA15_LEGACY_MODE: OK
NULL_RSA15_NO_FLAG: RSA-1.5 key transport is disabled (Bleichenbacher risk); set allowRSA15KeyTransport = true to opt in
NULL_RSA15_FLAG: OK
NON_TRANSPORT_DEFAULT: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
NON_TRANSPORT_NULL: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
LEGACY_NULL_STAYS_NULL: NULL
NESTED_DEFAULT: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'; add XMLSecurityKey::RSA_1_5 to allowedKeyAlgorithms (or call enableLegacyMode()) to opt in
NESTED_NULL: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
RETRIEVAL_DEFAULT: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'; add XMLSecurityKey::RSA_1_5 to allowedKeyAlgorithms (or call enableLegacyMode()) to opt in
RETRIEVAL_NULL: http://www.w3.org/2001/04/xmlenc#rsa-1_5
STATIC_FROM_DEFAULT: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'; add XMLSecurityKey::RSA_1_5 to allowedKeyAlgorithms (or call enableLegacyMode()) to opt in
STATIC_FROM_NULL: http://www.w3.org/2001/04/xmlenc#rsa-1_5
STATIC_LOCATE_DEFAULT: Key transport algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'; add XMLSecurityKey::RSA_1_5 to allowedKeyAlgorithms (or call enableLegacyMode()) to opt in
STATIC_LOCATE_NULL: http://www.w3.org/2001/04/xmlenc#rsa-1_5
