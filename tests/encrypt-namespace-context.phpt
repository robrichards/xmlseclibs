--TEST--
Element/Content round trip keeps inherited namespace bindings (prefixed and default), new and pre-existing ciphertext
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function roundTrip($xml, $type, $alg) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $box = $doc->getElementsByTagName('box')->item(0);
    $key = new XMLSecurityKey($alg);
    $key->generateSessionKey();
    $enc = new XMLSecEnc();
    if ($alg === XMLSecurityKey::AES256_CBC) {
        $enc->enableLegacyMode();
    }
    $enc->setNode($box);
    $enc->type = $type;
    $encData = $enc->encryptNode($key);
    $dec = new XMLSecEnc();
    if ($alg === XMLSecurityKey::AES256_CBC) {
        $dec->enableLegacyMode();
    }
    $dec->setNode($encData);
    $dec->type = $encData->getAttribute('Type');
    $octets = $dec->decryptNode($key, false);
    $dec->decryptNode($key, true);
    return array($doc, $octets);
}
function ns($doc, $uri, $name) {
    $n = $doc->getElementsByTagNameNS($uri, $name)->item(0);
    return $n === null ? 'MISSING' : $n->namespaceURI;
}

foreach (array(XMLSecurityKey::AES256_GCM, XMLSecurityKey::AES256_CBC) as $alg) {
    foreach (array(XMLSecEnc::Element, XMLSecEnc::Content) as $type) {
        $label = substr($alg, -8) . ' ' . substr($type, -7);
        // inherited prefix, on elements and on an attribute
        list($doc) = roundTrip('<env xmlns:p="urn:test"><box><p:item p:a="1"/></box></env>', $type, $alg);
        $item = $doc->getElementsByTagNameNS('urn:test', 'item')->item(0);
        print "$label prefix: " . ns($doc, 'urn:test', 'item') . ' attr=' . ($item && $item->hasAttributeNS('urn:test', 'a') ? 'yes' : 'NO') . "\n";
        // inherited default namespace
        list($doc) = roundTrip('<env xmlns="urn:d"><box><item/></box></env>', $type, $alg);
        print "$label default: " . ns($doc, 'urn:d', 'item') . "\n";
        // no-namespace content below a default namespace stays out of it
        list($doc) = roundTrip('<env xmlns="urn:d"><box><x xmlns=""><y/></x></box></env>', $type, $alg);
        $y = $doc->getElementsByTagName('y')->item(0);
        print "$label undeclared: " . var_export($y->namespaceURI, true) . "\n";
        // inner redeclaration wins
        list($doc) = roundTrip('<env xmlns:p="urn:outer"><box><p:x xmlns:p="urn:inner"><p:y/></p:x></box></env>', $type, $alg);
        print "$label inner: " . ns($doc, 'urn:inner', 'y') . ' outer-hits=' . $doc->getElementsByTagNameNS('urn:outer', 'y')->length . "\n";
    }
}
// Element mode serializes the in-scope bindings so a context-free decryptor sees them too
list(, $octets) = roundTrip('<env xmlns:p="urn:test"><box><p:i/></box></env>', XMLSecEnc::Element, XMLSecurityKey::AES256_GCM);
print "octets: $octets\n";
?>
--EXPECTF--
s256-gcm Element prefix: urn:test attr=yes
s256-gcm Element default: urn:d
s256-gcm Element undeclared: NULL
s256-gcm Element inner: urn:inner outer-hits=0
s256-gcm Content prefix: urn:test attr=yes
s256-gcm Content default: urn:d
s256-gcm Content undeclared: NULL
s256-gcm Content inner: urn:inner outer-hits=0
s256-cbc Element prefix: urn:test attr=yes
s256-cbc Element default: urn:d
s256-cbc Element undeclared: NULL
s256-cbc Element inner: urn:inner outer-hits=0
s256-cbc Content prefix: urn:test attr=yes
s256-cbc Content default: urn:d
s256-cbc Content undeclared: NULL
s256-cbc Content inner: urn:inner outer-hits=0
octets: <box xmlns:p="urn:test"><p:i/></box>
