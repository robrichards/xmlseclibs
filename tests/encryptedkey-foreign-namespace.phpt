--TEST--
A foreign-namespace EncryptedKey is not resolved, and fromEncryptedKeyElement requires key transport
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function document($keyInfo) {
    return '<Root xmlns:xenc="'.XMLSecEnc::XMLENCNS.'" xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS.'" xmlns:other="urn:other">'
        .'<xenc:EncryptedData>'
        .'<xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
        .'<ds:KeyInfo>'.$keyInfo.'</ds:KeyInfo>'
        .'<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedData></Root>';
}

function encryptedKey($prefix, $algorithm) {
    return '<'.$prefix.':EncryptedKey>'
        .'<xenc:EncryptionMethod Algorithm="'.$algorithm.'"/>'
        .'<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>'
        .'</'.$prefix.':EncryptedKey>';
}

function resolved($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    $dec->allowedKeyAlgorithms = XMLSecEnc::SUPPORTED_KEY_ALGORITHMS;
    $dec->allowedDataAlgorithms = XMLSecEnc::SUPPORTED_DATA_ALGORITHMS;
    $dec->setNode($dec->locateEncryptedData($doc));
    $key = $dec->locateKeyInfo($dec->locateKey());
    return $key->getAlgorithm().' encrypted='.($key->isEncrypted ? 'yes' : 'no');
}

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

$foreignAes = encryptedKey('other', XMLSecurityKey::AES128_CBC);
$foreignRsa = encryptedKey('other', XMLSecurityKey::RSA_OAEP_MGF1P);
$realRsa = encryptedKey('xenc', XMLSecurityKey::RSA_OAEP_MGF1P);

attempt('FOREIGN_AES', function () use ($foreignAes) {
    return resolved(document($foreignAes));
});
attempt('FOREIGN_RSA', function () use ($foreignRsa) {
    return resolved(document($foreignRsa));
});
attempt('REAL_RSA', function () use ($realRsa) {
    return resolved(document($realRsa));
});

function element($inner) {
    $doc = new DOMDocument();
    $doc->loadXML('<Root xmlns:xenc="'.XMLSecEnc::XMLENCNS.'" xmlns:other="urn:other">'.$inner.'</Root>');
    $node = $doc->getElementsByTagNameNS('urn:other', 'EncryptedKey')->item(0);
    if (! $node instanceof DOMElement) {
        throw new Exception('missing foreign EncryptedKey');
    }
    return $node;
}

attempt('FROM_FOREIGN_AES', function () use ($foreignAes) {
    return XMLSecurityKey::fromEncryptedKeyElement(element($foreignAes), 0, true, XMLSecEnc::SUPPORTED_KEY_ALGORITHMS, XMLSecEnc::SUPPORTED_DATA_ALGORITHMS)->getAlgorithm();
});
attempt('FROM_FOREIGN_RSA', function () use ($foreignRsa) {
    return XMLSecurityKey::fromEncryptedKeyElement(element($foreignRsa), 0, true, XMLSecEnc::SUPPORTED_KEY_ALGORITHMS, XMLSecEnc::SUPPORTED_DATA_ALGORITHMS)->getAlgorithm();
});
?>
--EXPECTF--
FOREIGN_AES: http://www.w3.org/2009/xmlenc11#aes256-gcm encrypted=no
FOREIGN_RSA: http://www.w3.org/2009/xmlenc11#aes256-gcm encrypted=no
REAL_RSA: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p encrypted=yes
FROM_FOREIGN_AES: EncryptedKey algorithm is not a supported key transport algorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
FROM_FOREIGN_RSA: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
