--TEST--
encryptNode() given a DOMDocument keeps a no-namespace descendant out of the root's default namespace
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function build() {
    $doc = new DOMDocument();
    $doc->loadXML('<root xmlns="urn:d"><named/></root>');
    $plain = $doc->createElement('plain');            /* created through the DOM: no namespace */
    $doc->documentElement->appendChild($plain);
    $plain->appendChild($doc->createElement('inner'));
    $doc->documentElement->appendChild($doc->createElementNS('urn:d', 'nsd'));
    return $doc;
}
function report($label, DOMDocument $d) {
    $out = array();
    foreach (array('named', 'plain', 'inner', 'nsd') as $name) {
        $e = $d->getElementsByTagName($name)->item(0);
        $out[] = $name . '=' . ($e === null ? 'MISSING' : var_export($e->namespaceURI, true));
    }
    print "$label: " . implode(' ', $out) . "\n";
}

$key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$key->generateSessionKey();

/* 1. The DOMDocument itself (Element mode). */
$doc = build();
$enc = new XMLSecEnc();
$enc->setNode($doc);
$enc->type = XMLSecEnc::Element;
$encDoc = $enc->encryptNode($key);
print 'source tree unchanged: ' . (($doc->getElementsByTagName('plain')->item(0)->hasAttribute('xmlns')) ? 'NO' : 'yes') . "\n";
$dec = new XMLSecEnc();
$dec->setNode($dec->locateEncryptedData($encDoc));
$dec->type = XMLSecEnc::Element;
print 'octets declare xmlns="": ' . ((strpos($dec->decryptNode($key, false), '<plain xmlns="">') !== false) ? 'yes' : 'NO') . "\n";
$dec->decryptNode($key, true);
report('document', $encDoc);

/* 2. The root element (Element mode), for comparison. */
$doc = build();
$enc = new XMLSecEnc();
$enc->setNode($doc->documentElement);
$enc->type = XMLSecEnc::Element;
$enc->encryptNode($key);
$dec = new XMLSecEnc();
$dec->setNode($dec->locateEncryptedData($doc));
$dec->type = XMLSecEnc::Element;
$dec->decryptNode($key);
report('root element', $doc);

/* 3. A document without a default namespace is serialized as before. */
$doc = new DOMDocument();
$doc->loadXML('<root><a/></root>');
$doc->documentElement->appendChild($doc->createElement('plain'));
$expected = $doc->saveXML();
$enc = new XMLSecEnc();
$enc->setNode($doc);
$enc->type = XMLSecEnc::Element;
$encDoc = $enc->encryptNode($key);
$dec = new XMLSecEnc();
$dec->setNode($dec->locateEncryptedData($encDoc));
$dec->type = XMLSecEnc::Element;
$strip = function ($x) { return preg_replace('/^<\?xml[^>]*\?>\s*/', '', $x); };
print 'plain document octets equal: ' . ($strip($dec->decryptNode($key, false)) === $strip($expected) ? 'yes' : 'NO') . "\n";
?>
--EXPECT--
source tree unchanged: yes
octets declare xmlns="": yes
document: named='urn:d' plain=NULL inner=NULL nsd='urn:d'
root element: named='urn:d' plain=NULL inner=NULL nsd='urn:d'
plain document octets equal: yes
