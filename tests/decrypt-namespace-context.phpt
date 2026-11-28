--TEST--
decryptNode() parses existing ciphertext in the namespace context of the EncryptedData parent
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* Ciphertext whose plaintext carries no namespace declarations, as written by earlier versions. */
function decryptIn($octets, $type, $parentXml) {
    $key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $key->generateSessionKey();
    $doc = new DOMDocument();
    $doc->loadXML($parentXml);
    $box = $doc->getElementsByTagName('box')->item(0);
    $cipher = base64_encode($key->encryptData($octets));
    $frag = $doc->createDocumentFragment();
    $frag->appendXML('<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="' . $type . '">'
        . '<xenc:CipherData><xenc:CipherValue>' . $cipher . '</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>');
    $box->appendChild($frag);
    $dec = new XMLSecEnc();
    $dec->setNode($box->firstChild);
    $dec->type = $type;
    $dec->decryptNode($key, true);
    return $doc;
}
function tryIt($label, $octets, $type) {
    try {
        $doc = decryptIn($octets, $type, '<env xmlns:p="urn:test" xmlns="urn:d"><box/></env>');
        $n = $doc->getElementsByTagName('item')->item(0);
        print "$label: ok " . ($n ? $n->namespaceURI : 'no-item') . "\n";
    } catch (Exception $e) {
        print "$label: " . $e->getMessage() . "\n";
    }
}
$E = XMLSecEnc::Element;
$C = XMLSecEnc::Content;
tryIt('element prefix', '<p:item/>', $E);
tryIt('element default', '<item/>', $E);
tryIt('element xmlns=""', '<item xmlns=""/>', $E);
tryIt('content prefix', 'a<p:item/>b', $C);
tryIt('xml declaration', '<?xml version="1.0"?>' . "\n" . '<p:item/>', $E);
tryIt('xml declaration latin1', "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><p:item>caf\xE9</p:item>", $E);
tryIt('xml declaration (content)', '<?xml version="1.0"?><p:item/>', $C);
tryIt('two elements', '<p:item/><p:item/>', $E);
tryIt('trailing text', '<p:item/>junk', $E);
tryIt('doctype', '<!DOCTYPE a [<!ENTITY x "y">]><item>&x;</item>', $E);
tryIt('doctype (content)', '<!DOCTYPE a><item/>', $C);
tryIt('wrapper escape', '</xmlenc-ctx><item/><xmlenc-ctx>', $C);
?>
--EXPECTF--
element prefix: ok urn:test
element default: ok urn:d
element xmlns="": ok 
content prefix: ok urn:test
xml declaration: ok urn:test
xml declaration latin1: ok urn:test
xml declaration (content): Error parsing decrypted XML
two elements: Error parsing decrypted XML
trailing text: Error parsing decrypted XML
doctype: Decrypted XML must not contain a DOCTYPE
doctype (content): Decrypted XML must not contain a DOCTYPE
wrapper escape: Error parsing decrypted XML
