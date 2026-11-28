--TEST--
A TypeError during reference processing leaves no validated nodes
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class TypeErrorAfterRef extends XMLSecurityDSig {
    public function processRefNode($refNode) {
        parent::processRefNode($refNode);
        throw new TypeError('stopped after reference');
    }
}

function pinnedKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

function loadSigned() {
    $doc = new DOMDocument();
    $doc->load(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
    return $doc;
}

function nodeState($nodes) {
    return $nodes === null ? 'null' : 'present';
}

$doc = loadSigned();
$dsig = new TypeErrorAfterRef();
try {
    $dsig->verifyDocument(pinnedKey(), $doc);
    print "DOC: not thrown\n";
} catch (TypeError $e) {
    print 'DOC: '.get_class($e).': '.$e->getMessage()."\n";
} catch (Throwable $e) {
    print 'DOC: '.get_class($e).': '.$e->getMessage()."\n";
}
print 'DOC_NODES: '.nodeState($dsig->getValidatedNodes())."\n";

$doc = loadSigned();
$dsig = new TypeErrorAfterRef();
$dsig->locateSignature($doc);
try {
    $dsig->validateReference();
    print "REF: not thrown\n";
} catch (TypeError $e) {
    print 'REF: '.get_class($e).': '.$e->getMessage()."\n";
} catch (Throwable $e) {
    print 'REF: '.get_class($e).': '.$e->getMessage()."\n";
}
print 'REF_NODES: '.nodeState($dsig->getValidatedNodes())."\n";
?>
--EXPECTF--
DOC: TypeError: stopped after reference
DOC_NODES: null
REF: TypeError: stopped after reference
REF_NODES: null
