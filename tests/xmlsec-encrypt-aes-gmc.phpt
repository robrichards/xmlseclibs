--TEST--
Basic Encryption
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

$arTests = array('AES128_GCM' => array('file'=>'aes128-gcm.xml', 'key'=>XMLSecurityKey::AES128_GCM),
	'AES192_GCM' => array('file'=>'aes192-gcm.xml', 'key'=>XMLSecurityKey::AES192_GCM),
	'AES256_GCM' => array('file'=>'aes256-gcm.xml', 'key'=>XMLSecurityKey::AES256_GCM));

foreach ($arTests AS $testName=>$testParams) {
	
	$testFile = $testParams['file'];
	$testKey = $testParams['key'];
	if (file_exists(dirname(__FILE__) . "/$testFile")) {
	    unlink(dirname(__FILE__) . "/$testFile");
	}
	
	print "$testName: ";
	// Travis not honoring SKIPIF
	if (version_compare(PHP_VERSION, '7.1.0') < 0) {
		print "EncryptedData\n";
		continue;
	}
	
	$dom = new DOMDocument();
	$dom->load(dirname(__FILE__) . '/basic-doc.xml');
	
	$objKey = new XMLSecurityKey($testKey);
	$objKey->generateSessionKey();
	
	$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
	$siteKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE, TRUE);
	
	$enc = new XMLSecEnc();
	$enc->setNode($dom->documentElement);
	$enc->encryptKey($siteKey, $objKey);
	
	$enc->type = XMLSecEnc::Element;
	$encNode = $enc->encryptNode($objKey);
	
	$dom->save(dirname(__FILE__) . "/$testFile");
	
	$root = $dom->documentElement;
	echo $root->localName."\n";
	
	unlink(dirname(__FILE__) . "/$testFile");
}

?>
--EXPECTF--
AES128_GCM: EncryptedData
AES192_GCM: EncryptedData
AES256_GCM: EncryptedData
