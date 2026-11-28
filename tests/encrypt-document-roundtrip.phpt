--TEST--
encryptNode() given a DOMDocument (XML declaration in the plaintext) and given the root element round-trip with namespaces intact
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
    . '<root xmlns="urn:d" xmlns:p="urn:test"><p:item p:a="1"><sub/></p:item></root>';
$key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$key->generateSessionKey();

function report($label, DOMDocument $d) {
    $item = $d->getElementsByTagNameNS('urn:test', 'item')->item(0);
    $sub = $d->getElementsByTagName('sub')->item(0);
    print "$label: root=" . $d->documentElement->namespaceURI
        . ' item=' . ($item ? $item->namespaceURI : 'MISSING')
        . ' attr=' . ($item && $item->hasAttributeNS('urn:test', 'a') ? 'yes' : 'NO')
        . ' sub=' . ($sub ? $sub->namespaceURI : 'MISSING') . "\n";
}

/* 1. The DOMDocument itself (Element mode): plaintext starts with the XML declaration. */
$doc = new DOMDocument();
$doc->loadXML($xml);
$enc = new XMLSecEnc();
$enc->setNode($doc);
$enc->type = XMLSecEnc::Element;
$encDoc = $enc->encryptNode($key);
print get_class($encDoc) . "\n";
$dec = new XMLSecEnc();
$encData = $dec->locateEncryptedData($encDoc);
$dec->setNode($encData);
$dec->type = XMLSecEnc::Element;
print 'octets equal: ' . ($dec->decryptNode($key, false) === $doc->saveXML() ? 'yes' : 'NO') . "\n";
$dec->decryptNode($key, true);
report('document', $encDoc);

/* 2. Content mode needs an owner document, so a DOMDocument is rejected. */
try {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $enc = new XMLSecEnc();
    $enc->setNode($doc);
    $enc->type = XMLSecEnc::Content;
    $enc->encryptNode($key);
    print "content: unexpected success\n";
} catch (Exception $e) {
    print 'content: ' . $e->getMessage() . "\n";
}

/* 3. The root element (Element mode). */
$doc = new DOMDocument();
$doc->loadXML($xml);
$enc = new XMLSecEnc();
$enc->setNode($doc->documentElement);
$enc->type = XMLSecEnc::Element;
$enc->encryptNode($key);
$dec = new XMLSecEnc();
$dec->setNode($dec->locateEncryptedData($doc));
$dec->type = XMLSecEnc::Element;
$dec->decryptNode($key);
report('root element', $doc);
?>
--EXPECTF--
DOMDocument
octets equal: yes
document: root=urn:d item=urn:test attr=yes sub=urn:d
content: Cannot resolve owner document for encryption
root element: root=urn:d item=urn:test attr=yes sub=urn:d
