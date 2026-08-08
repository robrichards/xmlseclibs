--TEST--
getRefNodeID rejects external URIs consistently with processRefNode
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

error_reporting(E_ALL);
$objDSig = new XMLSecurityDSig();

$cases = array(
    'EXTERNAL' => 'http://example.com/data.xml#abc',
    'QUERY'    => '?x=1',
    'BAREHASH' => '#',
    'FRAGMENT' => '#abc',
    'EMPTY'    => '',
);

foreach ($cases as $label => $uri) {
    $doc = new DOMDocument();
    $doc->loadXML('<ds:Reference xmlns:ds="http://www.w3.org/2000/09/xmldsig#" URI="'.htmlspecialchars($uri, ENT_QUOTES).'"/>');
    $id = $objDSig->getRefNodeID($doc->documentElement);
    echo "$label: ".var_export($id, true)."\n";
}
?>
--EXPECTF--
EXTERNAL: NULL
QUERY: NULL
BAREHASH: NULL
FRAGMENT: 'abc'
EMPTY: NULL
