--TEST--
Basic Verify
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;

$doc = new DOMDocument();
$arTests = array('SIGN_TEST'=>'sign-basic-test.xml');

foreach ($arTests AS $testName=>$testFile) {
	$doc->load(dirname(__FILE__) . "/$testFile");
	$objXMLSecDSig = new XMLSecurityDSig();
	
	$objDSig = $objXMLSecDSig->locateSignature($doc);
	if (! $objDSig) {
		throw new XMLSecLibsException("Cannot locate Signature Node");
	}
	$objXMLSecDSig->canonicalizeSignedInfo();
	$objXMLSecDSig->idKeys = array('wsu:Id');
	$objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
	
	$retVal = $objXMLSecDSig->validateReference();

	if (! $retVal) {
		throw new XMLSecLibsException("Reference Validation Failed");
	}
	
	$objKey = $objXMLSecDSig->locateKey();
	if (! $objKey ) {
		throw new XMLSecLibsException("We have no idea about the key");
	}
	$key = NULL;
	
	$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

	if (! $objKeyInfo->key && empty($key)) {
		$objKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE);
	}

	print $testName.": ";
	if ($objXMLSecDSig->verify($objKey)) {
		print "Signature validated!";
	} else {
		print "Failure!!!!!!!!";
	}
	print "\n";
}
?>
--EXPECTF--
SIGN_TEST: Signature validated!
