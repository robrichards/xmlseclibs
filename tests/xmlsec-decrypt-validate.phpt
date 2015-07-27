--TEST--
Decrypt and Verify namespaced document
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

/* When we need to locate our own key based on something like a key name */
function locateLocalKey($objKey) {
	/* In this example the key is identified by filename */
	$filename = $objKey->name;
	if (! empty($filename)) {
		$objKey->loadKey(dirname(__FILE__) . "/$filename", TRUE);
	} else {
	    $objKey->loadKey(dirname(__FILE__) . "/privkey.pem", TRUE);
	}
}

$arTests = array('SIGN_ENC_ELEMENT'=>'sign-encrypted-element.xml',
    'SIGN_ENC_CONTENT'=>'sign-encrypted-content.xml');

$doc = new DOMDocument();

foreach ($arTests AS $testName=>$testFile) {
	$output = NULL;
	print "$testName: ";

	$doc->load(dirname(__FILE__) . "/$testFile");
	
	try {
		$objenc = new XMLSecEnc();
		$encData = $objenc->locateEncryptedData($doc);
		if (! $encData) {
			throw new Exception("Cannot locate Encrypted Data");
		}
		$objenc->setNode($encData);
		$objenc->type = $encData->getAttribute("Type");
		if (! $objKey = $objenc->locateKey()) {
			throw new Exception("We know the secret key, but not the algorithm");
		}
		$key = NULL;
		
		if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
			if ($objKeyInfo->isEncrypted) {
				$objencKey = $objKeyInfo->encryptedCtx;
				locateLocalKey($objKeyInfo);
				$key = $objencKey->decryptKey($objKeyInfo);
			}
		}
		
		if (! $objKey->key && empty($key)) {
			locateLocalKey($objKey);
		}
		if (empty($objKey->key)) {
			$objKey->loadKey($key);
		}
		
		$token = NULL;

		$doc = null;
		if ($decrypt = $objenc->decryptNode($objKey, TRUE)) {
			$output = NULL;
			if ($decrypt instanceof DOMNode) {
				if ($decrypt instanceof DOMDocument) {	
					$doc = $decrypt;
				} else {
					$doc = $decrypt->ownerDocument;
				}
			} else {
				$output = $decrypt;
			}
		}
	} catch (Exception $e) {
		
	}
	
	if ($doc == null) {
		echo "FAILED\n";
		continue;
	}
	
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

	if ($objXMLSecDSig->verify($objKey)) {
		print "Signature validated!";
	} else {
		print "Failure!!!!!!!!";
	}
	print "\n";
}
?>
--EXPECTF--
SIGN_ENC_ELEMENT: Signature validated!
SIGN_ENC_CONTENT: Signature validated!
