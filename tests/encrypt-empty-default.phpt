--TEST--
xmlns="" is written for a no-namespace element under a default namespace, including a nested one, and attribute text is not a declaration
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function encrypt($doc, DOMNode $node, $type) {
    $key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $key->generateSessionKey();
    $enc = new XMLSecEnc();
    $enc->setNode($node);
    $enc->type = $type;
    $enc->encryptNode($key);
    $dec = new XMLSecEnc();
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = $type;
    $octets = $dec->decryptNode($key, false);
    $dec->decryptNode($key, true);
    return $octets;
}

/* Direct child created with createElement, so the DOM has no xmlns="" attribute. */
$doc = new DOMDocument();
$doc->loadXML('<env xmlns="urn:d"><box/></env>');
$box = $doc->getElementsByTagName('box')->item(0);
$x = $doc->createElement('x');
$x->appendChild($doc->createElement('y'));
$box->appendChild($x);
echo "content: ".encrypt($doc, $box, XMLSecEnc::Content)."\n";
$y = $doc->getElementsByTagName('y')->item(0);
echo "content y: ".var_export($y->namespaceURI, true)."\n";

/* Same element nested inside the encrypted element. */
$doc = new DOMDocument();
$doc->loadXML('<env xmlns="urn:d"><box><keep/></box></env>');
$box = $doc->getElementsByTagName('box')->item(0);
$x = $doc->createElement('x');
$x->appendChild($doc->createElement('y'));
$box->appendChild($x);
echo "nested: ".encrypt($doc, $box, XMLSecEnc::Element)."\n";
$y = $doc->getElementsByTagName('y')->item(0);
$keep = $doc->getElementsByTagName('keep')->item(0);
echo "nested y: ".var_export($y->namespaceURI, true)." keep: ".$keep->namespaceURI."\n";

/* The caller's element is not left with the temporary declaration. */
$doc = new DOMDocument();
$doc->loadXML('<env xmlns="urn:d"><box/></env>');
$box = $doc->getElementsByTagName('box')->item(0);
$x = $doc->createElement('x');
$box->appendChild($x);
$key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$key->generateSessionKey();
$enc = new XMLSecEnc();
$enc->setNode($box);
$enc->type = XMLSecEnc::Element;
$enc->encryptNode($key, false);
echo "unchanged: ".($x->hasAttribute('xmlns') ? 'yes' : 'no')."\n";

/* "xmlns:p=" inside an attribute value is not the element's own declaration. */
$doc = new DOMDocument();
$doc->loadXML('<env xmlns:p="urn:test"><box><p:item note="a&gt;b xmlns:p=fake">t</p:item></box></env>');
$box = $doc->getElementsByTagName('box')->item(0);
echo "attr: ".encrypt($doc, $box, XMLSecEnc::Element)."\n";
$item = $doc->getElementsByTagName('item')->item(0);
echo "attr item: ".$item->namespaceURI."\n";
?>
--EXPECTF--
content: <x xmlns=""><y/></x>
content y: NULL
nested: <box xmlns="urn:d"><keep/><x xmlns=""><y/></x></box>
nested y: NULL keep: urn:d
unchanged: no
attr: <box xmlns:p="urn:test"><p:item note="a&gt;b xmlns:p=fake">t</p:item></box>
attr item: urn:test
