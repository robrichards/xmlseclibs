--TEST--
encryptNode() can be retried on the same instance and replaces previous EncryptionMethod and CipherValue
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function directCount($node, $local) {
    $count = 0;
    if (! $node instanceof DOMElement) {
        return 0;
    }
    foreach ($node->childNodes as $child) {
        if ($child instanceof DOMElement
            && $child->localName === $local
            && $child->namespaceURI === XMLSecEnc::XMLENCNS) {
            $count++;
        }
    }
    return $count;
}

function cipherTextNodes($encrypted) {
    $count = 0;
    foreach ($encrypted->childNodes as $child) {
        if (! $child instanceof DOMElement
            || $child->localName !== 'CipherData'
            || $child->namespaceURI !== XMLSecEnc::XMLENCNS) {
            continue;
        }
        foreach ($child->childNodes as $value) {
            if (! $value instanceof DOMElement
                || $value->localName !== 'CipherValue'
                || $value->namespaceURI !== XMLSecEnc::XMLENCNS) {
                continue;
            }
            foreach ($value->childNodes as $text) {
                if ($text->nodeType === XML_TEXT_NODE && trim($text->textContent) !== '') {
                    $count++;
                }
            }
        }
    }
    return $count;
}

function decrypt($encrypted, $material) {
    $doc = new DOMDocument();
    $copy = $doc->importNode($encrypted, true);
    $doc->appendChild($copy);
    $dec = new XMLSecEnc();
    $dec->setNode($copy);
    $dec->type = XMLSecEnc::Element;
    $key = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
    $key->loadKey($material);
    return $dec->decryptNode($key, false);
}

function template($enc) {
    $property = new ReflectionProperty(XMLSecEnc::class, 'encdoc');
    $document = $property->getValue($enc);
    return $document instanceof DOMDocument ? $document->documentElement : null;
}

$original = '<child>payload</child>';
$doc = new DOMDocument();
$doc->loadXML($original);
$enc = new XMLSecEnc();
$enc->setNode($doc->documentElement);
$enc->type = XMLSecEnc::Element;
$unloaded = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
try {
    $enc->encryptNode($unloaded, false);
    echo "FAIL_ATTEMPT: no exception\n";
} catch (Exception $e) {
    echo 'FAIL_ATTEMPT: '.$e->getMessage()."\n";
}
$afterFail = template($enc);
echo 'AFTER_FAIL_METHODS: '.directCount($afterFail, 'EncryptionMethod')."\n";
echo 'AFTER_FAIL_CIPHER_TEXT: '.cipherTextNodes($afterFail)."\n";

$good = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
$material = $good->generateSessionKey();
$retried = $enc->encryptNode($good, false);
echo 'RETRY_METHODS: '.directCount($retried, 'EncryptionMethod')."\n";
echo 'RETRY_CIPHER_TEXT: '.cipherTextNodes($retried)."\n";
echo 'RETRY_DECRYPT: '.(decrypt($retried, $material) === $original ? 'yes' : 'no')."\n";

$doc = new DOMDocument();
$doc->loadXML($original);
$again = new XMLSecEnc();
$again->setNode($doc->documentElement);
$again->type = XMLSecEnc::Element;
$key = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
$material = $key->generateSessionKey();
$first = $again->encryptNode($key, false);
$snapshot = new DOMDocument();
$snapshot->appendChild($snapshot->importNode($first, true));
$second = $again->encryptNode($key, false);
echo 'FIRST_METHODS: '.directCount($snapshot->documentElement, 'EncryptionMethod')."\n";
echo 'SECOND_METHODS: '.directCount($second, 'EncryptionMethod')."\n";
echo 'FIRST_CIPHER_TEXT: '.cipherTextNodes($snapshot->documentElement)."\n";
echo 'SECOND_CIPHER_TEXT: '.cipherTextNodes($second)."\n";
echo 'FIRST_DECRYPT: '.(decrypt($snapshot->documentElement, $material) === $original ? 'yes' : 'no')."\n";
echo 'SECOND_DECRYPT: '.(decrypt($second, $material) === $original ? 'yes' : 'no')."\n";

$doc = new DOMDocument();
$doc->loadXML('<root><child>payload</child></root>');
$child = $doc->getElementsByTagName('child')->item(0);
$childXml = $doc->saveXML($child);
$refs = new XMLSecEnc();
$refs->addReference('child', $child, XMLSecEnc::Element);
try {
    $refs->encryptReferences($unloaded);
    echo "REF_FAIL: no exception\n";
} catch (Exception $e) {
    echo 'REF_FAIL: '.$e->getMessage()."\n";
}
$references = new ReflectionProperty(XMLSecEnc::class, 'references');
$stored = $references->getValue($refs);
$storedNode = $stored['child']['encnode'];
$storedElement = $storedNode instanceof DOMDocument ? $storedNode->documentElement : $storedNode;
echo 'REF_AFTER_FAIL_METHODS: '.directCount($storedElement, 'EncryptionMethod')."\n";
$refKey = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
$refMaterial = $refKey->generateSessionKey();
$refs->encryptReferences($refKey);
$encData = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);
echo 'REF_METHODS: '.directCount($encData, 'EncryptionMethod')."\n";
echo 'REF_CIPHER_TEXT: '.cipherTextNodes($encData)."\n";
echo 'REF_DECRYPT: '.(decrypt($encData, $refMaterial) === $childXml ? 'yes' : 'no')."\n";
?>
--EXPECTF--
FAIL_ATTEMPT: Key is not loaded
AFTER_FAIL_METHODS: 0
AFTER_FAIL_CIPHER_TEXT: 0
RETRY_METHODS: 1
RETRY_CIPHER_TEXT: 1
RETRY_DECRYPT: yes
FIRST_METHODS: 1
SECOND_METHODS: 1
FIRST_CIPHER_TEXT: 1
SECOND_CIPHER_TEXT: 1
FIRST_DECRYPT: yes
SECOND_DECRYPT: yes
REF_FAIL: Key is not loaded
REF_AFTER_FAIL_METHODS: 0
REF_METHODS: 1
REF_CIPHER_TEXT: 1
REF_DECRYPT: yes
