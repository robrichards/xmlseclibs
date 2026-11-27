--TEST--
Caller-supplied idNS mappings take precedence over document prefix declarations when resolving references
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

function sign($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $payload = $doc->getElementsByTagName('payload')->item(0);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->addReference(
        $payload,
        XMLSecurityDSig::SHA256,
        array(XMLSecurityDSig::EXC_C14N),
        array(
            'overwrite' => false,
            'prefix' => 'u',
            'prefix_ns' => WSU,
            'id_name' => 'Id',
        )
    );
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $key->loadKey(__DIR__.'/privkey.pem', true);
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

function check($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    if (! $dsig->locateSignature($doc)) {
        return 'no signature';
    }
    $dsig->canonicalizeSignedInfo();
    $dsig->idKeys = array('wsu:Id');
    $dsig->idNS = array('wsu' => WSU);
    try {
        $dsig->validateReference();
    } catch (Exception $e) {
        return $e->getMessage();
    }
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $key->loadKey(__DIR__.'/mycert.pem', true, true);
    $result = $dsig->verify($key);
    $nodes = $dsig->getValidatedNodes();
    $node = isset($nodes['signed']) ? $nodes['signed'] : null;
    $found = $node instanceof DOMElement ? $node->localName.' '.$node->textContent : 'missing';
    return ($result === 1 ? 'valid' : 'verify='.$result).' '.$found;
}

$conflict = sign(
    '<root xmlns:wsu="urn:unrelated"><payload xmlns:u="'.WSU.'" u:Id="signed">hello</payload></root>'
);
$plain = sign(
    '<root xmlns:wsu="'.WSU.'"><payload wsu:Id="signed">hello</payload></root>'
);

echo 'CONFLICT: '.check($conflict)."\n";
echo 'CONFLICT_MODIFIED: '.check(str_replace('>hello<', '>hell0<', $conflict))."\n";
echo 'PLAIN: '.check($plain)."\n";
?>
--EXPECTF--
CONFLICT: valid payload hello
CONFLICT_MODIFIED: Reference validation failed
PLAIN: valid payload hello
