--TEST--
Injection Verify
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;
$doc = new DOMDocument();
$arTests = array('SIGN_INJECTION_TEST'=>'sign-injection-test.xml');
foreach ($arTests AS $testName=>$testFile) {
	$doc->load(dirname(__FILE__) . "/$testFile");
	$objXMLSecDSig = new XMLSecurityDSig();
	
	$objDSig = $objXMLSecDSig->locateSignature($doc);
	if (! $objDSig) {
		throw new Exception("Cannot locate Signature Node");
	}
	$objXMLSecDSig->canonicalizeSignedInfo();
	$objXMLSecDSig->idKeys = array('wsu:Id');
	$objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
	
	try {
		$retVal = $objXMLSecDSig->validateReference();
		if (! $retVal) {
			throw new Exception("Reference Validation Failed");
		}
	} catch (Exception $e) {
		print "Injection detected!";
		continue;
	}	
	
	$objKey = $objXMLSecDSig->locateKey();
	if (! $objKey ) {
		throw new Exception("We have no idea about the key");
	}
	$key = NULL;
	
	$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
	if (! $objKeyInfo->key && empty($key)) {
		$objKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE);
	}
	print $testName.": ";
	if ($objXMLSecDSig->verify($objKey) === 1) {
		print "Failure!!!!!!!!";
	} else {
		print "Injection detected!";
	}
	print "\n";
}
?>
--EXPECTF--
SIGN_INJECTION_TEST: Injection detected!
