--TEST--
Verify with formatted X509Certificate
--FILE--
<?php
require __DIR__ . '/../vendor/autoload.php';
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;

$doc = new DOMDocument();
$arTests = array('SIGN_TEST_FORMATTED'=>'sign-formatted-test.xml');

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
	
	$retVal = $objXMLSecDSig->validateReference();

	if (! $retVal) {
		throw new Exception("Reference Validation Failed");
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
	if ($objXMLSecDSig->verify($objKey)) {
		print "Signature validated!";
	} else {
		print "Failure!!!!!!!!";
	}
	print "\n";
}
?>
--EXPECTF--
SIGN_TEST_FORMATTED: Signature validated!
