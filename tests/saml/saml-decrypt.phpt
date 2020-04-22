--TEST--
Basic Decryption
--FILE--
<?php
require(dirname(__FILE__) . '/../../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;

 // Travis not honoring SKIPIF
 if (version_compare(PHP_VERSION, '7.1.0') < 0) {
	print "KYzsRqRzQY5qp+bv9T8bHA/AvsI=\n";
	exit;
 }

/* When we need to locate our own key based on something like a key name */
function locateLocalKey($objKey) {
	/* In this example the key is identified by filename */
	$filename = $objKey->name;
	if (! empty($filename)) {
		$objKey->loadKey(dirname(__FILE__) . "/$filename", TRUE);
	} else {
		$objKey->loadKey(dirname(__FILE__) . "/encryption_rsa.key", TRUE);
	}
}

$testFile = "saml-encrypted.xml";

$output = NULL;

$doc = new DOMDocument();
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

	if ($decrypt = $objenc->decryptNode($objKey, TRUE)) {
		$output = NULL;
		
		$xpath = new DOMXpath($decrypt->ownerDocument);
		$xpath->registerNamespace('saml2p', 'urn:oasis:names:tc:SAML:2.0:protocol');
		$xpath->registerNamespace('saml2', 'urn:oasis:names:tc:SAML:2.0:assertion');
		
		$xpathQuery = 'string(/saml2p:Response/saml2:EncryptedAssertion/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute/saml2:AttributeValue/saml2:NameID/text())';
		
		$nameID = $xpath->evaluate($xpathQuery);
		
		print "$nameID\n";
		
	} else {
		throw new Exception("Unable to decrypt node");;
	}
} catch (Exception $e) {
	var_dump($e);
}
	
?>
--EXPECTF--
KYzsRqRzQY5qp+bv9T8bHA/AvsI=
