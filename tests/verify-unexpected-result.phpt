--TEST--
verify() throws when the key returns anything other than integer 1 or 0
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$dir = dirname(__FILE__);

class FixedResultKey extends XMLSecurityKey
{
    public $fixed;

    public function verifySignature($data, $signature)
    {
        return $this->fixed;
    }
}

$doc = new DOMDocument();
$doc->loadXML('<Root xmlns="urn:test"><Item>payload</Item></Root>');
$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signer->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::ENVELOPED), array('force_uri' => true));
$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
$key->loadKey($dir . '/privkey.pem', true);
$signer->sign($key);
$signer->appendSignature($doc->documentElement);
$xml = $doc->saveXML();

$doc = new DOMDocument();
$doc->loadXML($xml);
$dsig = new XMLSecurityDSig();
$dsig->locateSignature($doc);
$dsig->canonicalizeSignedInfo();

$real = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
$real->loadKey($dir . '/mycert.pem', true, true);

$dsig->validateReference();
echo 'verify valid: ' . var_export($dsig->verify($real), true) . ', nodes ' . count($dsig->getValidatedNodes()) . "\n";

$fixed = new FixedResultKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
foreach (array(-1, true, '1', null) as $value) {
    $fixed->fixed = $value;
    try {
        $r = $dsig->verify($fixed);
        echo var_export($value, true) . ': returned ' . var_export($r, true) . "\n";
    } catch (Exception $e) {
        echo var_export($value, true) . ': throws: ' . $e->getMessage() . ', nodes ' . var_export($dsig->getValidatedNodes(), true) . "\n";
    }
    $dsig->validateReference();
}

$fixed->fixed = 0;
echo 'zero: ' . var_export($dsig->verify($fixed), true) . ', nodes ' . var_export($dsig->getValidatedNodes(), true) . "\n";
$dsig->validateReference();
$fixed->fixed = 1;
echo 'one: ' . var_export($dsig->verify($fixed), true) . ', nodes ' . count($dsig->getValidatedNodes()) . "\n";
?>
--EXPECT--
verify valid: 1, nodes 1
-1: throws: Key returned an unexpected verification result, nodes NULL
true: throws: Key returned an unexpected verification result, nodes NULL
'1': throws: Key returned an unexpected verification result, nodes NULL
NULL: throws: Key returned an unexpected verification result, nodes NULL
zero: 0, nodes NULL
one: 1, nodes 1
