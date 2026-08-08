--TEST--
Object Id under nested Signature resolves before enveloped strip
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->loadXML('<Envelope><Payload>data</Payload></Envelope>');

$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objDSig->idKeys = array('xml:id');

$wrapped = $objDSig->sigNode->ownerDocument->createElement('Wrapped');
$wrapped->setAttributeNS('http://www.w3.org/XML/1998/namespace', 'xml:id', 'obj1');
$wrapped->appendChild($objDSig->sigNode->ownerDocument->createTextNode('inside-object'));
$objDSig->addObject($wrapped);

$objDSig->addReference(
    $wrapped,
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::ENVELOPED, XMLSecurityDSig::EXC_C14N),
    array(
        'id_name' => 'id',
        'overwrite' => false,
        'prefix' => 'xml',
        'prefix_ns' => 'http://www.w3.org/XML/1998/namespace',
    )
);

$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$objDSig->sign($key);
$objDSig->appendSignature($doc->documentElement);

$verify = new XMLSecurityDSig();
$verify->idKeys = array('xml:id');
$pub = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$pub->loadKey(dirname(__FILE__) . '/mycert.pem', true);
$verify->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA256);
$verify->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);

try {
    $nodes = $verify->verifyDocument($pub, $doc);
    echo isset($nodes['obj1']) ? "OBJECT_REF: OK\n" : "OBJECT_REF: missing node\n";
} catch (Exception $e) {
    echo "OBJECT_REF: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
OBJECT_REF: OK
