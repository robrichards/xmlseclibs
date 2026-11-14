--TEST--
RSA-OAEP rejects malformed, unsupported and ambiguous parameters without borrowing descendants
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function keyDocument($parameters, $algorithm = XMLSecurityKey::RSA_OAEP) {
    $doc = new DOMDocument();
    $doc->loadXML('<e:EncryptedKey xmlns:e="'.XMLSecEnc::XMLENCNS
        .'" xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS.'" xmlns:e11="'.XMLSecEnc::XMLENC11NS.'">'
        .'<e:EncryptionMethod Algorithm="'.$algorithm.'">'.$parameters.'</e:EncryptionMethod>'
        .'</e:EncryptedKey>');
    return $doc;
}

function expectRejection($name, $operation) {
    try {
        $operation();
        echo "$name: NOT rejected\n";
    } catch (Exception $e) {
        echo "$name: rejected\n";
    }
}

$digest = '<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'"/>';
$mgf = '<e11:MGF Algorithm="'.XMLSecEnc::XMLENC11NS.'mgf1sha1"/>';
$cases = array(
    'unknown digest' => '<ds:DigestMethod Algorithm="urn:unsupported"/>',
    'unknown MGF' => '<e11:MGF Algorithm="urn:unsupported"/>',
    'digest URI as MGF' => '<e11:MGF Algorithm="'.XMLSecurityDSig::SHA256.'"/>',
    'missing digest URI' => '<ds:DigestMethod/>',
    'missing MGF URI' => '<e11:MGF/>',
    'empty digest URI' => '<ds:DigestMethod Algorithm=""/>',
    'empty MGF URI' => '<e11:MGF Algorithm=""/>',
    'duplicate digest' => $digest.$digest,
    'conflicting digest' => $digest.'<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA256.'"/>',
    'duplicate MGF' => $mgf.$mgf,
    'duplicate label' => '<e:OAEPparams/><e:OAEPparams/>',
    'invalid base64' => '<e:OAEPparams>@@@</e:OAEPparams>',
    'missing base64 padding' => '<e:OAEPparams>YQ</e:OAEPparams>',
    'invalid base64 pad bits' => '<e:OAEPparams>YR==</e:OAEPparams>',
    'extra base64 padding' => '<e:OAEPparams>YQ===</e:OAEPparams>',
    'nested label' => '<e:OAEPparams><e:Label>YQ==</e:Label></e:OAEPparams>',
    'nested digest content' => '<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'"><e:Child/></ds:DigestMethod>',
    'digest text content' => '<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'">sha1</ds:DigestMethod>',
    'method text content' => 'unexpected text',
    'wrong digest namespace' => '<e:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'"/>',
    'wrong MGF namespace' => '<e:MGF Algorithm="'.XMLSecEnc::XMLENC11NS.'mgf1sha1"/>',
    'wrong label namespace' => '<ds:OAEPparams>YQ==</ds:OAEPparams>',
    'nested parameter' => '<e:Wrapper>'.$digest.'</e:Wrapper>',
);
foreach ($cases as $name => $parameters) {
    expectRejection($name, function () use ($parameters) {
        $doc = keyDocument($parameters);
        XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
    });
}

expectRejection('old identifier MGF forbidden', function () use ($mgf) {
    $doc = keyDocument($mgf, XMLSecurityKey::RSA_OAEP_MGF1P);
    XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
});
expectRejection('duplicate EncryptionMethod', function () {
    $doc = keyDocument('');
    $doc->documentElement->appendChild($doc->documentElement->firstChild->cloneNode(true));
    XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
});

$doc = keyDocument('');
$method = $doc->documentElement->removeChild($doc->documentElement->firstChild);
$child = $doc->documentElement->appendChild($doc->createElementNS(XMLSecEnc::XMLENCNS, 'e:EncryptedKey'));
$child->appendChild($method);
$enc = new XMLSecEnc();
echo 'no descendant method: '.($enc->locateKey($doc->documentElement) === null ? 'OK' : 'FAIL')."\n";

expectRejection('OAEP algorithm policy', function () {
    $doc = keyDocument('');
    $enc = new XMLSecEnc();
    $enc->allowedKeyAlgorithms = array(XMLSecurityKey::RSA_OAEP_MGF1P);
    $enc->locateKey($doc->documentElement);
});

foreach (array(XMLSecurityKey::RSA_SHA256_MGF1, XMLSecurityKey::RSA_1_5, XMLSecurityKey::AES128_GCM) as $algorithm) {
    expectRejection('non-OAEP configuration', function () use ($algorithm) {
        $key = new XMLSecurityKey($algorithm, array('type' => 'private'));
        $key->setOAEPParameters();
    });
}
expectRejection('old identifier non-SHA1 MGF', function () {
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'private'));
    $key->setOAEPParameters(XMLSecurityDSig::SHA256, XMLSecEnc::XMLENC11NS.'mgf1sha256');
});
?>
--EXPECTF--
unknown digest: rejected
unknown MGF: rejected
digest URI as MGF: rejected
missing digest URI: rejected
missing MGF URI: rejected
empty digest URI: rejected
empty MGF URI: rejected
duplicate digest: rejected
conflicting digest: rejected
duplicate MGF: rejected
duplicate label: rejected
invalid base64: rejected
missing base64 padding: rejected
invalid base64 pad bits: rejected
extra base64 padding: rejected
nested label: rejected
nested digest content: rejected
digest text content: rejected
method text content: rejected
wrong digest namespace: rejected
wrong MGF namespace: rejected
wrong label namespace: rejected
nested parameter: rejected
old identifier MGF forbidden: rejected
duplicate EncryptionMethod: rejected
no descendant method: OK
OAEP algorithm policy: rejected
non-OAEP configuration: rejected
non-OAEP configuration: rejected
non-OAEP configuration: rejected
old identifier non-SHA1 MGF: rejected
