--TEST--
XMLSecEnc::$allowedDataAlgorithms defaults to DEFAULT_DATA_ALGORITHMS (AES-GCM only)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const ENC_NS = 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

/* Encrypt '<root>payload</root>' with $dataAlg, wrapping the session key with RSA-OAEP-MGF1P. */
function encryptedDocument($dataAlg) {
    $public = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $symmetric = new XMLSecurityKey($dataAlg);
    $symmetric->generateSessionKey();
    $enc->encryptKey($public, $symmetric);
    $enc->encryptNode($symmetric);
    return $doc;
}

/* Full path: locateKey, locateKeyInfo, decryptKey, decryptNode. */
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

/* decryptNode() with a caller-supplied key (no locateKey). */
function decryptNodeDirect($dataAlg, ?callable $configure = null) {
    $key = new XMLSecurityKey($dataAlg);
    $key->generateSessionKey();
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $enc->encryptNode($key);

    $dec = new XMLSecEnc();
    if ($configure) {
        $configure($dec);
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dec->decryptNode($key, true);
    return $doc->documentElement->textContent === 'payload' ? 'OK' : 'FAIL';
}

$legacy = function ($dec) { $dec->enableLegacyMode(); };
$nullList = function ($dec) { $dec->allowedDataAlgorithms = null; };

/* 1. Default value, and the constant is not mutated by enableLegacyMode(). */
$enc = new XMLSecEnc();
echo 'DEFAULT: '.($enc->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS ? 'DEFAULT_DATA_ALGORITHMS' : var_export($enc->allowedDataAlgorithms, true))."\n";
echo 'LEGACY_CONST: '.(XMLSecEnc::LEGACY_DATA_ALGORITHMS === array(
    XMLSecurityKey::AES128_CBC,
    XMLSecurityKey::AES192_CBC,
    XMLSecurityKey::AES256_CBC,
    XMLSecurityKey::TRIPLEDES_CBC,
) ? 'yes' : 'no')."\n";

/* 2. AES-GCM decrypts with the default list (locateKey / decryptKey / decryptNode). */
foreach (array(
    'GCM128' => XMLSecurityKey::AES128_GCM,
    'GCM192' => XMLSecurityKey::AES192_GCM,
    'GCM256' => XMLSecurityKey::AES256_GCM,
) as $name => $alg) {
    attempt($name, function () use ($alg) {
        return decrypt(encryptedDocument($alg));
    });
    attempt($name.'_NODE', function () use ($alg) {
        return decryptNodeDirect($alg);
    });
}

/* 3. CBC and TripleDES-CBC are rejected by default, including decryptNode() alone. */
foreach (array(
    'CBC128' => XMLSecurityKey::AES128_CBC,
    'CBC192' => XMLSecurityKey::AES192_CBC,
    'CBC256' => XMLSecurityKey::AES256_CBC,
    'TRIPLEDES' => XMLSecurityKey::TRIPLEDES_CBC,
) as $name => $alg) {
    attempt($name.'_DEFAULT', function () use ($alg) {
        return decrypt(encryptedDocument($alg));
    });
    attempt($name.'_NODE', function () use ($alg) {
        return decryptNodeDirect($alg);
    });
}

/* 4. enableLegacyMode() accepts CBC and TripleDES-CBC, without duplicating entries. */
foreach (array(
    'CBC128' => XMLSecurityKey::AES128_CBC,
    'CBC192' => XMLSecurityKey::AES192_CBC,
    'CBC256' => XMLSecurityKey::AES256_CBC,
    'TRIPLEDES' => XMLSecurityKey::TRIPLEDES_CBC,
    'GCM256' => XMLSecurityKey::AES256_GCM,
) as $name => $alg) {
    attempt('LEGACY_'.$name, function () use ($alg, $legacy) {
        return decrypt(encryptedDocument($alg), $legacy);
    });
}
attempt('LEGACY_CBC256_NODE', function () use ($legacy) {
    return decryptNodeDirect(XMLSecurityKey::AES256_CBC, $legacy);
});
$dec = new XMLSecEnc();
$dec->enableLegacyMode();
$dec->enableLegacyMode();
$legacyList = array_merge(XMLSecEnc::DEFAULT_DATA_ALGORITHMS, XMLSecEnc::LEGACY_DATA_ALGORITHMS);
echo 'LEGACY_LIST: '.($dec->allowedDataAlgorithms === $legacyList ? 'yes' : 'no')."\n";
echo 'LEGACY_CONST_UNCHANGED: '.(count(XMLSecEnc::DEFAULT_DATA_ALGORITHMS) === 3 && count(XMLSecEnc::LEGACY_DATA_ALGORITHMS) === 4 ? 'yes' : 'no')."\n";
$dec = new XMLSecEnc();
$dec->allowedDataAlgorithms = array(XMLSecurityKey::AES256_CBC, XMLSecurityKey::AES128_GCM);
$dec->enableLegacyMode();
$once = 0;
foreach ($dec->allowedDataAlgorithms as $algorithm) {
    if ($algorithm === XMLSecurityKey::AES256_CBC) {
        $once++;
    }
}
echo 'LEGACY_NO_DUPLICATE: '.($once === 1 && in_array(XMLSecurityKey::AES128_CBC, $dec->allowedDataAlgorithms, true) ? 'yes' : 'no')."\n";

/* 5. A null list applies no allowlist and stays null. */
attempt('NULL_STAYS_NULL', function () {
    $dec = new XMLSecEnc();
    $dec->allowedDataAlgorithms = null;
    $dec->enableLegacyMode();
    return var_export($dec->allowedDataAlgorithms, true);
});
foreach (array(
    'NULL_CBC256' => XMLSecurityKey::AES256_CBC,
    'NULL_TRIPLEDES' => XMLSecurityKey::TRIPLEDES_CBC,
    'NULL_GCM128' => XMLSecurityKey::AES128_GCM,
) as $name => $alg) {
    attempt($name, function () use ($alg, $nullList) {
        return decrypt(encryptedDocument($alg), $nullList);
    });
}

/* 6. A custom list replaces the default. */
$only128 = function ($dec) {
    $dec->allowedDataAlgorithms = array(XMLSecurityKey::AES128_GCM);
};
$onlyCbc = function ($dec) {
    $dec->allowedDataAlgorithms = array(XMLSecurityKey::AES256_CBC);
};
attempt('CUSTOM_GCM128', function () use ($only128) {
    return decrypt(encryptedDocument(XMLSecurityKey::AES128_GCM), $only128);
});
attempt('CUSTOM_GCM256_NARROW', function () use ($only128) {
    return decrypt(encryptedDocument(XMLSecurityKey::AES256_GCM), $only128);
});
attempt('CUSTOM_CBC256', function () use ($onlyCbc) {
    return decrypt(encryptedDocument(XMLSecurityKey::AES256_CBC), $onlyCbc);
});
attempt('CUSTOM_GCM_ON_CBC_LIST', function () use ($onlyCbc) {
    return decrypt(encryptedDocument(XMLSecurityKey::AES256_GCM), $onlyCbc);
});

/* 7. The list is enforced on the EncryptedKey context produced by locateKeyInfo(). */
attempt('PROPAGATED_DEFAULT', function () {
    $doc = encryptedDocument(XMLSecurityKey::AES256_GCM);
    $dec = new XMLSecEnc();
    $dec->setNode($dec->locateEncryptedData($doc));
    $transport = $dec->locateKeyInfo($dec->locateKey());
    return $transport->encryptedCtx->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS ? 'yes' : 'no';
});
attempt('PROPAGATED_CBC', function () {
    $doc = encryptedDocument(XMLSecurityKey::AES256_GCM);
    $dec = new XMLSecEnc();
    $dec->setNode($dec->locateEncryptedData($doc));
    $transport = $dec->locateKeyInfo($dec->locateKey());
    $cbc = encryptedDocument(XMLSecurityKey::AES256_CBC);
    $transport->encryptedCtx->setNode($transport->encryptedCtx->locateEncryptedData($cbc));
    $transport->encryptedCtx->type = XMLSecEnc::Element;
    $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
    $key->generateSessionKey();
    $transport->encryptedCtx->decryptNode($key, false);
    return 'unexpected success';
});

/* 8. Static helpers use the same default; explicit null opts out. */
$doc = encryptedDocument(XMLSecurityKey::AES256_GCM);
$encData = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);
$encKey = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
attempt('STATIC_FROM_OMITTED', function () use ($encKey) {
    $key = XMLSecurityKey::fromEncryptedKeyElement($encKey);
    return $key->encryptedCtx->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS ? 'DEFAULT' : 'other';
});
attempt('STATIC_FROM_NULL', function () use ($encKey) {
    $key = XMLSecurityKey::fromEncryptedKeyElement($encKey, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, null);
    return var_export($key->encryptedCtx->allowedDataAlgorithms, true);
});
attempt('STATIC_LOCATE_OMITTED', function () use ($encData) {
    $base = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $key = XMLSecEnc::staticLocateKeyInfo($base, $encData);
    return $key->encryptedCtx->allowedDataAlgorithms === XMLSecEnc::DEFAULT_DATA_ALGORITHMS ? 'DEFAULT' : 'other';
});
attempt('STATIC_LOCATE_NULL', function () use ($encData) {
    $base = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $key = XMLSecEnc::staticLocateKeyInfo($base, $encData, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, null);
    return var_export($key->encryptedCtx->allowedDataAlgorithms, true);
});

/*
 * 9. A symmetric algorithm on EncryptedKey is key wrap / key transport, not data
 *    encryption. AES-KW is not implemented; a supported symmetric cipher used as
 *    the EncryptedKey algorithm is still rejected as key transport, including
 *    when that URI is on the data list.
 */
function encryptedKeyDocument($keyAlg, $dataAlg = null) {
    $dataAlg = $dataAlg ?? XMLSecurityKey::AES256_GCM;
    return '<Root '.ENC_NS.'><xenc:EncryptedData Type="'.XMLSecEnc::Element.'">'
        .'<xenc:EncryptionMethod Algorithm="'.$dataAlg.'"/>'
        .'<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.$keyAlg.'"/>'
        .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>'
        .'<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></Root>';
}
function resolveKey($xml, ?callable $configure = null) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    if ($configure) {
        $configure($dec);
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    return $dec->locateKeyInfo($dec->locateKey())->getAlgorithm();
}
$kw = 'http://www.w3.org/2001/04/xmlenc#kw-aes256';
attempt('KW_DEFAULT', function () use ($kw) {
    return resolveKey(encryptedKeyDocument($kw));
});
attempt('KW_ON_LISTS', function () use ($kw) {
    return resolveKey(encryptedKeyDocument($kw), function ($dec) use ($kw) {
        $dec->allowedDataAlgorithms[] = $kw;
        $dec->allowedKeyAlgorithms[] = $kw;
    });
});
attempt('KW_AS_DATA', function () use ($kw) {
    $doc = new DOMDocument();
    $doc->loadXML(encryptedKeyDocument(XMLSecurityKey::RSA_OAEP_MGF1P, $kw));
    $dec = new XMLSecEnc();
    $dec->setNode($dec->locateEncryptedData($doc));
    $key = $dec->locateKey();
    return $key === null ? 'null' : $key->getAlgorithm();
});
attempt('CBC_KEK_DEFAULT', function () {
    return resolveKey(encryptedKeyDocument(XMLSecurityKey::AES128_CBC));
});
attempt('CBC_KEK_LEGACY', function () use ($legacy) {
    return resolveKey(encryptedKeyDocument(XMLSecurityKey::AES128_CBC), $legacy);
});
?>
--EXPECTF--
DEFAULT: DEFAULT_DATA_ALGORITHMS
LEGACY_CONST: yes
GCM128: OK
GCM128_NODE: OK
GCM192: OK
GCM192_NODE: OK
GCM256: OK
GCM256_NODE: OK
CBC128_DEFAULT: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
CBC128_NODE: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
CBC192_DEFAULT: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
CBC192_NODE: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
CBC256_DEFAULT: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
CBC256_NODE: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
TRIPLEDES_DEFAULT: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
TRIPLEDES_NODE: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
LEGACY_CBC128: OK
LEGACY_CBC192: OK
LEGACY_CBC256: OK
LEGACY_TRIPLEDES: OK
LEGACY_GCM256: OK
LEGACY_CBC256_NODE: OK
LEGACY_LIST: yes
LEGACY_CONST_UNCHANGED: yes
LEGACY_NO_DUPLICATE: yes
NULL_STAYS_NULL: NULL
NULL_CBC256: OK
NULL_TRIPLEDES: OK
NULL_GCM128: OK
CUSTOM_GCM128: OK
CUSTOM_GCM256_NARROW: Data encryption algorithm is not allowed: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
CUSTOM_CBC256: OK
CUSTOM_GCM_ON_CBC_LIST: Data encryption algorithm is not allowed: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
PROPAGATED_DEFAULT: yes
PROPAGATED_CBC: Data encryption algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
STATIC_FROM_OMITTED: DEFAULT
STATIC_FROM_NULL: NULL
STATIC_LOCATE_OMITTED: DEFAULT
STATIC_LOCATE_NULL: NULL
KW_DEFAULT: Unable to locate algorithm for this Encrypted Key
KW_ON_LISTS: Unable to locate algorithm for this Encrypted Key
KW_AS_DATA: null
CBC_KEK_DEFAULT: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
CBC_KEK_LEGACY: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
