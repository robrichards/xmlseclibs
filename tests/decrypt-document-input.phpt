--TEST--
decryptNode() on a DOMDocument: only a document whose root is CipherData is accepted; an EncryptedData document is not
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$xml = '<root xmlns="urn:d" xmlns:p="urn:test"><p:item p:a="1"><sub/></p:item></root>';
$key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$key->generateSessionKey();

function encrypted($xml, $key) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $enc = new XMLSecEnc();
    $enc->setNode($doc);
    $enc->type = XMLSecEnc::Element;
    return $enc->encryptNode($key);            /* a DOMDocument whose root is EncryptedData */
}

/* 1. The returned encryption document is not itself a decryptable node. */
foreach (array(false, true) as $replace) {
    try {
        $encDoc = encrypted($xml, $key);
        $dec = new XMLSecEnc();
        $dec->setNode($encDoc);
        $dec->type = XMLSecEnc::Element;
        $dec->decryptNode($key, $replace);
        print "document node: unexpected success\n";
    } catch (Exception $e) {
        print 'document node, replace=' . var_export($replace, true) . ': ' . $e->getMessage() . "\n";
    }
}

/* 2. The element form works and returns the restored root element. */
$encDoc = encrypted($xml, $key);
$dec = new XMLSecEnc();
$dec->setNode($encDoc->documentElement);
$dec->type = XMLSecEnc::Element;
$root = $dec->decryptNode($key);
print get_class($root) . ' ' . $root->namespaceURI . ' ' . $root->ownerDocument->getElementsByTagNameNS('urn:test', 'item')->length . "\n";

/* 3. A document whose root is CipherData reaches the document-returning branch. */
$encDoc = encrypted($xml, $key);
$cipherData = $encDoc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'CipherData')->item(0);
$cipherDoc = new DOMDocument();
$cipherDoc->appendChild($cipherDoc->importNode($cipherData, true));
$dec = new XMLSecEnc();
$dec->setNode($cipherDoc);
$dec->type = XMLSecEnc::Element;
$result = $dec->decryptNode($key);
$item = $result->getElementsByTagNameNS('urn:test', 'item')->item(0);
$sub = $result->getElementsByTagName('sub')->item(0);
print get_class($result) . ' root=' . $result->documentElement->namespaceURI
    . ' item=' . $item->namespaceURI . ' attr=' . ($item->hasAttributeNS('urn:test', 'a') ? 'yes' : 'NO')
    . ' sub=' . $sub->namespaceURI . "\n";
?>
--EXPECT--
document node, replace=false: Cannot locate encrypted data
document node, replace=true: Cannot locate encrypted data
DOMElement urn:d 1
DOMDocument root=urn:d item=urn:test attr=yes sub=urn:d
