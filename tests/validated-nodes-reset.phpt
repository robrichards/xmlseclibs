--TEST--
A failed verification leaves no validated nodes
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function pinnedKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

function privateKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    return $objKey;
}

function nodeState($nodes) {
    if ($nodes === null) {
        return 'null';
    }
    if ($nodes === array()) {
        return 'empty';
    }
    return 'present';
}

/* A successful call, then an unsigned document on the same object. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
$dsig = new XMLSecurityDSig();
try {
    $nodes = $dsig->verifyDocument(pinnedKey(), $doc);
    print 'REUSE_FIRST: '.(count($nodes) > 0 ? 'ok' : 'empty')."\n";
} catch (Exception $e) {
    print 'REUSE_FIRST: '.$e->getMessage()."\n";
}

$unsigned = new DOMDocument();
$unsigned->load(dirname(__FILE__) . '/basic-doc.xml');
try {
    $dsig->verifyDocument(pinnedKey(), $unsigned);
    print "REUSE_SECOND: not rejected\n";
} catch (Exception $e) {
    print 'REUSE_SECOND: '.$e->getMessage()."\n";
}
print 'REUSE_NODES: '.nodeState($dsig->getValidatedNodes())."\n";

/* A later reference fails after an earlier one succeeded. */
$doc = new DOMDocument();
$doc->loadXML('<Root><A>one</A><B>two</B></Root>');
$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signer->addReference(
    $doc->getElementsByTagName('A')->item(0),
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::EXC_C14N)
);
$signer->addReference(
    $doc->getElementsByTagName('B')->item(0),
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::EXC_C14N)
);
$signer->sign(privateKey());
$signer->appendSignature($doc->documentElement);

$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$xpath->query('//ds:Reference')->item(1)->setAttribute('URI', 'http://example.test/outside');

$verifier = new XMLSecurityDSig();
$verifier->locateSignature($doc);
$verifier->canonicalizeSignedInfo();
try {
    $verifier->validateReference();
    print "LATER: not rejected\n";
} catch (Exception $e) {
    print 'LATER: '.$e->getMessage()."\n";
}
print 'LATER_NODES: '.nodeState($verifier->getValidatedNodes())."\n";

/* verify() keeps nodes when it returns 1 and clears them otherwise. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
$verifier = new XMLSecurityDSig();
$verifier->locateSignature($doc);
$verifier->canonicalizeSignedInfo();
$verifier->validateReference();
$kept = $verifier->verify(pinnedKey());
print 'KEEP: '.($kept === 1 ? 'valid' : 'invalid').' '.nodeState($verifier->getValidatedNodes())."\n";

$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$sigValue = $xpath->query('//ds:SignatureValue')->item(0);
while ($sigValue->firstChild) {
    $sigValue->removeChild($sigValue->firstChild);
}
$sigValue->appendChild($doc->createTextNode('AAAA'));
$failed = $verifier->verify(pinnedKey());
print 'CLEAR: '.($failed === 1 ? 'valid' : 'invalid').' '.nodeState($verifier->getValidatedNodes())."\n";
?>
--EXPECTF--
REUSE_FIRST: ok
REUSE_SECOND: Cannot locate Signature Node
REUSE_NODES: null
LATER: Reference URI must be a same-document reference
LATER_NODES: null
KEEP: valid present
CLEAR: invalid null
