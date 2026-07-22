--TEST--
Max Transform Checks
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;

$doc = new DOMDocument();
$arTests = array('MAX_TRANSFORMS'=>'xml-max-transforms.xml',
	'MAX_NAMESPACES'=>'xml-max-namespaces.xml');

foreach ($arTests AS $testName=>$testFile) {
	try {
		$doc->load(dirname(__FILE__) . "/$testFile");
		$objXMLSecDSig = new XMLSecurityDSig();
		$objXMLSecDSig->allowXPathTransforms = true;
		
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
		if ($objXMLSecDSig->verify($objKey) === 1) {
			print "Signature validated!";
		} else {
			print "Failure!!!!!!!!";
		}
	} catch (Exception $e) {
		print $e->getMessage();
	}
	print "\n";
}

/* Stricter override: reject with a lower limit than the default. */
try {
	$doc->load(dirname(__FILE__) . '/xml-max-transforms.xml');
	$objXMLSecDSig = new XMLSecurityDSig();
	$objXMLSecDSig->allowXPathTransforms = true;
	$objXMLSecDSig->maxXPathTransforms = 2;
	$objDSig = $objXMLSecDSig->locateSignature($doc);
	$objXMLSecDSig->canonicalizeSignedInfo();
	$objXMLSecDSig->idKeys = array('wsu:Id');
	$objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
	$objXMLSecDSig->validateReference();
	print "STRICT_TRANSFORMS: unexpected success\n";
} catch (Exception $e) {
	print $e->getMessage()."\n";
}

/* Relaxed override: raise limits so these fixtures pass the DoS checks. */
try {
	$doc->load(dirname(__FILE__) . '/xml-max-transforms.xml');
	$objXMLSecDSig = new XMLSecurityDSig();
	$objXMLSecDSig->allowXPathTransforms = true;
	$objXMLSecDSig->maxXPathTransforms = 100;
	$objDSig = $objXMLSecDSig->locateSignature($doc);
	$objXMLSecDSig->canonicalizeSignedInfo();
	$objXMLSecDSig->idKeys = array('wsu:Id');
	$objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
	$objXMLSecDSig->validateReference();
	print "RELAXED_TRANSFORMS: limit not enforced\n";
} catch (Exception $e) {
	$msg = $e->getMessage();
	if (strpos($msg, 'Too many XPath Transformations') === 0) {
		print "RELAXED_TRANSFORMS: still capped\n";
	} else {
		print "RELAXED_TRANSFORMS: limit not enforced\n";
	}
}

try {
	$doc->load(dirname(__FILE__) . '/xml-max-namespaces.xml');
	$objXMLSecDSig = new XMLSecurityDSig();
	$objXMLSecDSig->allowXPathTransforms = true;
	$objXMLSecDSig->maxXPathNamespaces = 100;
	$objDSig = $objXMLSecDSig->locateSignature($doc);
	$objXMLSecDSig->canonicalizeSignedInfo();
	$objXMLSecDSig->idKeys = array('wsu:Id');
	$objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
	$objXMLSecDSig->validateReference();
	print "RELAXED_NAMESPACES: limit not enforced\n";
} catch (Exception $e) {
	$msg = $e->getMessage();
	if (strpos($msg, 'Too many namespaces in XPath Transformation') === 0) {
		print "RELAXED_NAMESPACES: still capped\n";
	} else {
		print "RELAXED_NAMESPACES: limit not enforced\n";
	}
}
?>
--EXPECTF--
Too many XPath Transformations found (12) with a max allowed of 5
Too many namespaces in XPath Transformation found (27)  with a max allowed of 20
Too many XPath Transformations found (12) with a max allowed of 2
RELAXED_TRANSFORMS: limit not enforced
RELAXED_NAMESPACES: limit not enforced
