--TEST--
RSA-OAEP encryption defaults to SHA-256; absent DigestMethod still decrypts as SHA-1
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

function freshKey($algorithm) {
    $key = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $params = $key->getOAEPParameters();
    return $params['digest'].' '.$params['mgf'];
}

/* Encrypt a session key and round-trip it under the default key-transport allowlist. */
function roundTrip($algorithm, $configure = null) {
    $public = new XMLSecurityKey($algorithm, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    if ($configure !== null) {
        $configure($public);
    }
    $session = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $session->generateSessionKey();
    $plainKey = $session->key;
    $doc = new DOMDocument();
    $doc->loadXML('<root>payload</root>');
    $enc = new XMLSecEnc();
    $enc->setNode($doc->documentElement);
    $enc->type = XMLSecEnc::Element;
    $enc->encryptKey($public, $session);
    $enc->encryptNode($session);

    $xp = new DOMXPath($doc);
    $xp->registerNamespace('e', XMLSecEnc::XMLENCNS);
    $xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
    $xp->registerNamespace('e11', XMLSecEnc::XMLENC11NS);
    $method = $xp->query('//e:EncryptedKey/e:EncryptionMethod')->item(0);
    if (! $method instanceof DOMElement) {
        return 'missing EncryptionMethod';
    }
    if ($method->getAttribute('Algorithm') !== $algorithm) {
        return 'wrong algorithm '.$method->getAttribute('Algorithm');
    }
    $digests = $xp->query('ds:DigestMethod', $method);
    if ($digests->length !== 1 || $digests->item(0)->namespaceURI !== XMLSecurityDSig::XMLDSIGNS) {
        return 'digest count '.$digests->length;
    }
    $digestAlg = $digests->item(0)->getAttribute('Algorithm');
    $mgfs = $xp->query('e11:MGF', $method);
    if ($algorithm === XMLSecurityKey::RSA_OAEP) {
        if ($mgfs->length !== 1 || $mgfs->item(0)->namespaceURI !== XMLSecEnc::XMLENC11NS) {
            return 'mgf count '.$mgfs->length;
        }
        $mgfAlg = $mgfs->item(0)->getAttribute('Algorithm');
    } elseif ($mgfs->length !== 0) {
        return 'mgf1p emitted MGF';
    } else {
        $mgfAlg = '-';
    }

    $dec = new XMLSecEnc();
    if ($dec->allowedKeyAlgorithms !== XMLSecEnc::DEFAULT_KEY_ALGORITHMS) {
        return 'allowlist not default';
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transport = $dec->locateKeyInfo($dataKey);
    if ($transport->encryptedCtx->allowedKeyAlgorithms !== XMLSecEnc::DEFAULT_KEY_ALGORITHMS) {
        return 'EncryptedKey allowlist not propagated';
    }
    $transport->loadKey(__DIR__ . '/privkey.pem', true);
    $unwrapped = $transport->encryptedCtx->decryptKey($transport);
    if (! hash_equals($plainKey, $unwrapped)) {
        return 'session mismatch';
    }
    $dataKey->loadKey($unwrapped);
    $dec->decryptNode($dataKey, true);
    if ($doc->documentElement->textContent !== 'payload') {
        return 'payload mismatch';
    }
    $params = $transport->getOAEPParameters();
    if ($params['digest'] !== $digestAlg || ($mgfAlg !== '-' && $params['mgf'] !== $mgfAlg)) {
        return 'resolved parameters differ';
    }
    return $digestAlg.' '.$mgfAlg;
}

function wrappedDocument($algorithm, $hash, $mgfHash) {
    static $private = null;
    if ($private === null) {
        $private = PublicKeyLoader::load(file_get_contents(__DIR__ . '/privkey.pem'));
    }
    $session = random_bytes(32);
    $wrapped = $private->getPublicKey()->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash($hash)->withMGFHash($mgfHash)->encrypt($session);
    $aes = new AES('gcm');
    $aes->setKey($session);
    $iv = random_bytes(12);
    $aes->setNonce($iv);
    $ct = $aes->encrypt('<root>payload</root>');
    $xml = '<Root><xenc:EncryptedData '.ENC_NS.' Type="'.XMLSecEnc::Element.'">'
        .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
        .'<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="'.$algorithm.'"/>'
        .'<xenc:CipherData><xenc:CipherValue>'.base64_encode($wrapped).'</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedKey></ds:KeyInfo>'
        .'<xenc:CipherData><xenc:CipherValue>'.base64_encode($iv.$ct.$aes->getTag(16)).'</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedData></Root>';
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    return $doc;
}

function decryptWrapped(DOMDocument $doc) {
    $dec = new XMLSecEnc();
    if ($dec->allowedKeyAlgorithms !== XMLSecEnc::DEFAULT_KEY_ALGORITHMS) {
        return 'allowlist not default';
    }
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transport = $dec->locateKeyInfo($dataKey);
    $params = $transport->getOAEPParameters();
    $transport->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
    $dec->decryptNode($dataKey, true);
    if ($doc->documentElement->textContent !== 'payload') {
        return 'payload mismatch';
    }
    return 'OK '.$params['digest'].' '.$params['mgf'];
}

$sha1 = XMLSecurityDSig::SHA1;
$mgf1 = XMLSecEnc::XMLENC11NS.'mgf1sha1';

attempt('CTOR OAEP', function () {
    return freshKey(XMLSecurityKey::RSA_OAEP);
});
attempt('CTOR MGF1P', function () {
    return freshKey(XMLSecurityKey::RSA_OAEP_MGF1P);
});
attempt('DEFAULT OAEP', function () {
    return roundTrip(XMLSecurityKey::RSA_OAEP);
});
attempt('DEFAULT MGF1P', function () {
    return roundTrip(XMLSecurityKey::RSA_OAEP_MGF1P);
});
attempt('EXPLICIT SHA1 OAEP', function () use ($sha1, $mgf1) {
    return roundTrip(XMLSecurityKey::RSA_OAEP, function ($key) use ($sha1, $mgf1) {
        $key->setOAEPParameters($sha1, $mgf1);
    });
});
attempt('EXPLICIT SHA1 MGF1P', function () use ($sha1) {
    return roundTrip(XMLSecurityKey::RSA_OAEP_MGF1P, function ($key) use ($sha1) {
        $key->setOAEPParameters($sha1);
    });
});
attempt('NOARG OAEP', function () {
    return roundTrip(XMLSecurityKey::RSA_OAEP, function ($key) {
        $key->setOAEPParameters();
    });
});

foreach (array('OAEP' => XMLSecurityKey::RSA_OAEP, 'MGF1P' => XMLSecurityKey::RSA_OAEP_MGF1P) as $label => $algorithm) {
    attempt("ABSENT SHA1 $label", function () use ($algorithm) {
        return decryptWrapped(wrappedDocument($algorithm, 'sha1', 'sha1'));
    });
    /* Digest differs from SHA-1; MGF matches the absent-element default. */
    attempt("ABSENT DIGEST SHA256 $label", function () use ($algorithm) {
        return decryptWrapped(wrappedDocument($algorithm, 'sha256', 'sha1'));
    });
}
/* MGF differs from MGF1-SHA1; digest matches the absent-element default. */
attempt('ABSENT MGF SHA256 OAEP', function () {
    return decryptWrapped(wrappedDocument(XMLSecurityKey::RSA_OAEP, 'sha1', 'sha256'));
});
?>
--EXPECTF--
CTOR OAEP: http://www.w3.org/2001/04/xmlenc#sha256 http://www.w3.org/2009/xmlenc11#mgf1sha256
CTOR MGF1P: http://www.w3.org/2001/04/xmlenc#sha256 http://www.w3.org/2009/xmlenc11#mgf1sha1
DEFAULT OAEP: http://www.w3.org/2001/04/xmlenc#sha256 http://www.w3.org/2009/xmlenc11#mgf1sha256
DEFAULT MGF1P: http://www.w3.org/2001/04/xmlenc#sha256 -
EXPLICIT SHA1 OAEP: http://www.w3.org/2000/09/xmldsig#sha1 http://www.w3.org/2009/xmlenc11#mgf1sha1
EXPLICIT SHA1 MGF1P: http://www.w3.org/2000/09/xmldsig#sha1 -
NOARG OAEP: http://www.w3.org/2000/09/xmldsig#sha1 http://www.w3.org/2009/xmlenc11#mgf1sha1
ABSENT SHA1 OAEP: OK http://www.w3.org/2000/09/xmldsig#sha1 http://www.w3.org/2009/xmlenc11#mgf1sha1
ABSENT DIGEST SHA256 OAEP: Failure decrypting Data
ABSENT SHA1 MGF1P: OK http://www.w3.org/2000/09/xmldsig#sha1 http://www.w3.org/2009/xmlenc11#mgf1sha1
ABSENT DIGEST SHA256 MGF1P: Failure decrypting Data
ABSENT MGF SHA256 OAEP: Failure decrypting Data
