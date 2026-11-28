--TEST--
verifyDocument() checks the signature before reference processing
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class RecordingDSig extends XMLSecurityDSig {
    public $referenceCalls = 0;
    public $refNodeCalls = 0;

    public function validateReference() {
        $this->referenceCalls++;
        return parent::validateReference();
    }

    public function processRefNode($refNode) {
        $this->refNodeCalls++;
        return parent::processRefNode($refNode);
    }
}

function pinnedKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

/*
 * The reference URI would throw "Reference URI must be a same-document
 * reference" if reference processing ran. The signature bytes are wrong.
 */
$xml = <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<Root>
  <Value>hello</Value>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="http://example.test/outside">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAA</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
  </ds:Signature>
</Root>
XML;

$doc = new DOMDocument();
$doc->loadXML($xml);
$objDSig = new RecordingDSig();
try {
    $objDSig->verifyDocument(pinnedKey(), $doc);
    print "SIG: not rejected\n";
} catch (Exception $e) {
    print 'SIG: '.get_class($e).': '.$e->getMessage()."\n";
}
print 'SIG_REFERENCES: '.$objDSig->referenceCalls."\n";
print 'SIG_REFNODES: '.$objDSig->refNodeCalls."\n";
?>
--EXPECTF--
SIG: Exception: Signature validation failed
SIG_REFERENCES: 0
SIG_REFNODES: 0
