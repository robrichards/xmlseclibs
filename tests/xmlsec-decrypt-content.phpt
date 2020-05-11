--TEST--
Basic Decryption: Content
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;

/* When we need to locate our own key based on something like a key name */
function locateLocalKey($objKey) {
	/* In this example the key is identified by filename */
	$filename = $objKey->name;
	if (!empty($filename)) {
		$objKey->loadKey(dirname(__FILE__) . "/$filename", true);
	} else {
	    $objKey->loadKey(dirname(__FILE__) . "/privkey.pem", true);
	}
}

$arTests = array('AOESP_SHA1'=>'oaep_sha1-res.xml',
   'AOESP_SHA1_CONTENT'=>'oaep_sha1-content-res.xml',
   'AES-128-CBC'=>'basic-doc-encrypted-aes128-cbc.xml',
   'AES-192-CBC'=>'basic-doc-encrypted-aes192-cbc.xml',
   'AES-256-CBC'=>'basic-doc-encrypted-aes256-cbc.xml',
   '3DES-CBC'=>'basic-doc-encrypted-tripledes-cbc.xml');

$doc = new DOMDocument();

foreach ($arTests as $testName => $testFile) {
	$output = null;
	print "$testName: ";

	$doc->load(dirname(__FILE__) . "/$testFile");
	
	try {
		$objenc = new XMLSecEnc();
		$encData = $objenc->locateEncryptedData($doc);
		if (!$encData) {
			throw new Exception("Cannot locate Encrypted Data");
		}
		$objenc->setNode($encData);
		$objenc->type = $encData->getAttribute("Type");
		if (!$objKey = $objenc->locateKey()) {
			throw new Exception("We know the secret key, but not the algorithm");
		}
		$key = null;
		
		if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
			if ($objKeyInfo->isEncrypted) {
				$objencKey = $objKeyInfo->encryptedCtx;
				locateLocalKey($objKeyInfo);
				$key = $objencKey->decryptKey($objKeyInfo);
			}
		}
		
		if (!$objKey->key && empty($key)) {
			locateLocalKey($objKey);
		}
		if (empty($objKey->key)) {
			$objKey->loadKey($key);
		}
		
		$token = null;

		if ($decrypt = $objenc->decryptNode($objKey, true)) {
			$output = null;
			if ($decrypt instanceof DOMNode) {
				if ($decrypt instanceof DOMDocument) {	
					$output = $decrypt->saveXML();
				} else {
					$output = $decrypt->ownerDocument->saveXML();
				}
			} else {
				$output = $decrypt;
			}
		}
	} catch (Exception $e) {

	}

	$outfile = dirname(__FILE__) . "/basic-doc.xml";
	$res = null;
	if (file_exists($outfile)) {
	    $resDoc = new DOMDocument();
	    $resDoc->load($outfile);
		$res = $resDoc->saveXML();
		if ($output == $res) {
			print "Passed\n";
			continue;
		}
	}
	print "Failed\n";
	
}
?>
--EXPECTF--
AOESP_SHA1: Passed
AOESP_SHA1_CONTENT: Passed
AES-128-CBC: Passed
AES-192-CBC: Passed
AES-256-CBC: Passed
3DES-CBC: Passed
