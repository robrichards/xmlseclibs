--TEST--
Test for ds:RetrievalMethod.
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;

$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . "/retrievalmethod-findkey.xml");

$objenc = new XMLSecEnc();
$encData = $objenc->locateEncryptedData($doc);
if (! $encData) {
	throw new Exception("Cannot locate Encrypted Data");
}
$objenc->setNode($encData);
$objenc->setType($encData->getAttribute("Type"));
$objKey = $objenc->locateKey();

$objKeyInfo = $objenc->locateKeyInfo($objKey);

if (!$objKeyInfo->getIsEncrypted()) {
	throw new Exception('Expected $objKeyInfo to refer to an encrypted key by now.');
}

echo "OK\n";

?>
--EXPECTF--
OK
