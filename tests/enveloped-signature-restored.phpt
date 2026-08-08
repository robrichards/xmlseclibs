--TEST--
Enveloped transform restores Signature before validating later references
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$doc = new DOMDocument();
$doc->loadXML('<Envelope><Payload>data</Payload></Envelope>');

$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signer->addReference(
    $doc,
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::ENVELOPED, XMLSecurityDSig::EXC_C14N),
    array('force_uri' => true)
);

$object = $signer->addObject('inside-object');
$object->setAttribute('Id', 'obj1');
$signer->addReference(
    $object,
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::EXC_C14N),
    array('overwrite' => false)
);

$privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$privateKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
$signer->sign($privateKey);
$signer->appendSignature($doc->documentElement);

$verifier = new XMLSecurityDSig();
$publicKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$publicKey->loadKey(dirname(__FILE__) . '/mycert.pem', true);
$verifier->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA256);
$verifier->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);

try {
    $nodes = $verifier->verifyDocument($publicKey, $doc);
    echo "VERIFY: OK\n";
    echo "SIGNATURES: ".$doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Signature')->length."\n";
    echo isset($nodes['obj1']) ? "OBJECT: OK\n" : "OBJECT: missing\n";
} catch (Exception $e) {
    echo "VERIFY: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
VERIFY: OK
SIGNATURES: 1
OBJECT: OK
