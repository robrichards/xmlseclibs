--TEST--
getRefNodeID handles URI without fragment without PHP warnings
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

error_reporting(E_ALL);
$doc = new DOMDocument();
$doc->loadXML('<ds:Reference xmlns:ds="http://www.w3.org/2000/09/xmldsig#" URI="?x=1"/>');
$objDSig = new XMLSecurityDSig();
$id = $objDSig->getRefNodeID($doc->documentElement);
var_export($id);
echo "\n";
?>
--EXPECTF--
NULL
