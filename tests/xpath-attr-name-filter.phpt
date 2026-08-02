--TEST--
XPath::filterAttrName accepts hyphenated attribute names
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\Utils\XPath;

$result = XPath::filterAttrName('wsu:Id-value_1.');
echo $result."\n";
echo (preg_last_error() === PREG_NO_ERROR ? 'OK' : 'FAIL')."\n";
?>
--EXPECTF--
wsu:Id-value_1.
OK
