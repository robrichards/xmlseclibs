--TEST--
Protocol lookups still find EncryptionMethod, CipherValue, KeyInfo, and Signature when the document rebinds library prefixes
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function attempt($name, $operation) {
    try {
        echo "$name: ".$operation()."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}

function directChildren($node, $local) {
    $count = 0;
    foreach ($node->childNodes as $child) {
        if ($child instanceof DOMElement
            && $child->localName === $local
            && $child->namespaceURI === XMLSecEnc::XMLENCNS) {
            $count++;
        }
    }
    return $count;
}

function encryptedDocument() {
    $doc = new DOMDocument();
    $doc->loadXML('<root><child>payload</child></root>');
    $session = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
    $session->generateSessionKey();
    $transport = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
    $transport->loadKey(__DIR__.'/mycert.pem', true, true);
    $enc = new XMLSecEnc();
    $enc->setNode($doc->getElementsByTagName('child')->item(0));
    $enc->type = XMLSecEnc::Element;
    $enc->encryptKey($transport, $session);
    $enc->encryptNode($session);
    $xml = $doc->saveXML();
    $xml = str_replace('xmlns:xenc', 'xmlns:enc', $xml);
    $xml = str_replace('xenc:', 'enc:', $xml);
    $rebound = new DOMDocument();
    $rebound->loadXML($xml);
    $decoys = array(
        'xenc' => 'urn:other',
        'xmlsecenc' => 'urn:other',
        'xmlencr' => 'urn:other',
        'xmlsecdsig' => 'urn:other',
    );
    $encData = $rebound->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);
    foreach (array($rebound->documentElement, $encData) as $element) {
        foreach ($decoys as $prefix => $namespace) {
            $element->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:'.$prefix, $namespace);
        }
    }
    return $rebound;
}

function decrypt($doc) {
    $dec = new XMLSecEnc();
    $encData = $dec->locateEncryptedData($doc);
    if (! $encData instanceof DOMElement) {
        throw new Exception('missing EncryptedData');
    }
    $dec->setNode($encData);
    $dec->type = $encData->getAttribute('Type');
    $dataKey = $dec->locateKey();
    if (! $dataKey instanceof XMLSecurityKey) {
        throw new Exception('missing data key');
    }
    $transportKey = $dec->locateKeyInfo($dataKey);
    if (! $transportKey instanceof XMLSecurityKey || ! $transportKey->isEncrypted) {
        throw new Exception('missing key info');
    }
    $transportKey->loadKey(__DIR__.'/privkey.pem', true);
    $dataKey->loadKey($transportKey->encryptedCtx->decryptKey($transportKey));
    $dec->decryptNode($dataKey, true);
    return trim($doc->documentElement->textContent);
}

attempt('DECRYPT', function () {
    return decrypt(encryptedDocument());
});

attempt('FOREIGN_SIBLING', function () {
    $doc = encryptedDocument();
    $encData = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);
    $foreign = $doc->createElementNS('urn:other', 'xmlsecenc:EncryptionMethod');
    $foreign->setAttribute('Algorithm', 'urn:other:method');
    $encData->appendChild($foreign);
    $dec = new XMLSecEnc();
    $dec->setNode($encData);
    $key = $dec->locateKey();
    return $key instanceof XMLSecurityKey ? $key->getAlgorithm() : 'missing';
});

attempt('DUPLICATE', function () {
    $doc = encryptedDocument();
    $encData = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);
    $method = null;
    foreach ($encData->childNodes as $child) {
        if ($child instanceof DOMElement
            && $child->localName === 'EncryptionMethod'
            && $child->namespaceURI === XMLSecEnc::XMLENCNS) {
            $method = $child;
            break;
        }
    }
    if (! $method instanceof DOMElement) {
        throw new Exception('missing EncryptionMethod');
    }
    $encData->appendChild($method->cloneNode(true));
    if (directChildren($encData, 'EncryptionMethod') !== 2) {
        throw new Exception('expected two EncryptionMethod elements');
    }
    $dec = new XMLSecEnc();
    $dec->setNode($encData);
    $dec->locateKey();
    return 'not rejected';
});

function signedDocument() {
    $doc = new DOMDocument();
    $doc->load(__DIR__.'/basic-doc.xml');
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->addReference(
        $doc,
        XMLSecurityDSig::SHA256,
        array(
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            XMLSecurityDSig::EXC_C14N,
        )
    );
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $key->loadKey(__DIR__.'/privkey.pem', true);
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    $signature = $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Signature')->item(0);
    $signedInfo = $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'SignedInfo')->item(0);
    foreach (array($doc->documentElement, $signature, $signedInfo) as $element) {
        $element->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:secdsig', 'urn:other');
    }
    return $doc->saveXML();
}

function verifySigned($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if (! $dsig->locateSignature($doc)) {
        return 'no signature';
    }
    $dsig->canonicalizeSignedInfo();
    $dsig->validateReference();
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $key->loadKey(__DIR__.'/mycert.pem', true, true);
    $result = $dsig->verify($key);
    return $result === 1 ? 'valid' : 'verify='.$result;
}

$signed = signedDocument();
attempt('SIGNED', function () use ($signed) {
    return verifySigned($signed);
});
attempt('MODIFIED', function () use ($signed) {
    return verifySigned(str_replace('Hello, World!', 'Hello, World?', $signed));
});
?>
--EXPECTF--
DECRYPT: payload
FOREIGN_SIBLING: http://www.w3.org/2009/xmlenc11#aes128-gcm
DUPLICATE: Multiple EncryptionMethod elements
SIGNED: valid
MODIFIED: Reference validation failed
