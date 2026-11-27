--TEST--
verify() throws when locateKey() yields a key-transport SignatureMethod and the allowlist is null
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$xml = '<r xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS.'">'
    .'<ds:Signature>'
    .'<ds:SignedInfo>'
    .'<ds:CanonicalizationMethod Algorithm="'.XMLSecurityDSig::EXC_C14N.'"/>'
    .'<ds:SignatureMethod Algorithm="'.XMLSecurityKey::RSA_OAEP_MGF1P.'"/>'
    .'<ds:Reference URI="">'
    .'<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA256.'"/>'
    .'<ds:DigestValue>AA==</ds:DigestValue>'
    .'</ds:Reference>'
    .'</ds:SignedInfo>'
    .'<ds:SignatureValue>AA==</ds:SignatureValue>'
    .'</ds:Signature>'
    .'</r>';

$doc = new DOMDocument();
$doc->loadXML($xml);
$dsig = new XMLSecurityDSig();
$dsig->allowedSignatureAlgorithms = null;
if (! $dsig->locateSignature($doc)) {
    echo "NO SIGNATURE\n";
    exit;
}
$key = $dsig->locateKey();
if (! $key instanceof XMLSecurityKey) {
    echo "NO KEY\n";
    exit;
}
echo 'ALGORITHM: '.$key->getAlgorithm()."\n";
echo 'verifySignature: '.$key->verifySignature('payload', 'signature')."\n";
try {
    $result = $dsig->verify($key);
    echo 'RETURN: '.var_export($result, true)."\n";
    echo 'TRUTHY: '.($result ? 'yes' : 'no')."\n";
} catch (Exception $e) {
    echo 'EXCEPTION: '.$e->getMessage()."\n";
}
?>
--EXPECTF--
ALGORITHM: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
verifySignature: 0
EXCEPTION: Key type 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' cannot be used for signatures; use a signature key type such as XMLSecurityKey::RSA_SHA256 or XMLSecurityKey::HMAC_SHA1
