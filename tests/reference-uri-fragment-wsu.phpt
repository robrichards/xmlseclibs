--TEST--
Reference URI fragments are matched exactly for a namespaced ID attribute
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

/* The Id holds both quote characters: a'"b */
$xml = '<root xmlns:wsu="' . WSU . '">'
    . '<payload wsu:Id="a\'&quot;b">hello</payload>'
    . '<other wsu:Id="x\'y">world</other>'
    . '</root>';

function signWsu($xml)
{
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $dsig->addReference(
        $doc->getElementsByTagName('payload')->item(0),
        XMLSecurityDSig::SHA256,
        array(XMLSecurityDSig::EXC_C14N),
        array(
            'overwrite' => false,
            'prefix' => 'wsu',
            'prefix_ns' => WSU,
            'id_name' => 'Id',
        )
    );
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    return $doc;
}

function newVerifier($legacy, $idNS)
{
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    $dsig->idKeys = array('wsu:Id');
    if ($idNS) {
        $dsig->idNS = array('wsu' => WSU);
    }
    $dsig->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA256);
    $dsig->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);
    return $dsig;
}

function verifyWsu($doc, $legacy, $idNS)
{
    $pub = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $pub->loadKey(dirname(__FILE__) . '/mycert.pem', true);
    try {
        $nodes = newVerifier($legacy, $idNS)->verifyDocument($pub, $doc);
        $ids = array_keys($nodes);
        return 'verified ' . implode(',', $ids);
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

function checkWsu($doc, $legacy, $idNS)
{
    $dsig = newVerifier($legacy, $idNS);
    $dsig->locateSignature($doc);
    $dsig->canonicalizeSignedInfo();
    try {
        return $dsig->validateReference() ? 'valid' : 'invalid';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

function withUri($uri)
{
    global $xml;
    $doc = signWsu($xml);
    $refs = $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Reference');
    $refs->item(0)->setAttribute('URI', $uri);
    return $doc;
}

$doc = signWsu($xml);
echo 'URI: ', $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Reference')->item(0)->getAttribute('URI'), "\n";

/* Prefix mapped through idNS, and through the document element's binding. */
foreach (array('idNS' => true, 'document binding' => false) as $label => $idNS) {
    foreach (array('default' => false, 'legacy' => true) as $mode => $legacy) {
        echo "verify $label $mode: ", verifyWsu(signWsu($xml), $legacy, $idNS), "\n";
    }
}

/* A fragment that differs by one quote character does not resolve. */
$variants = array(
    'double quote only' => 'a"b',
    'single quote only' => "a'b",
    'extra double quote' => "a'\"\"b",
    'extra single quote' => "a''\"b",
    'no quotes' => 'ab',
);
foreach ($variants as $label => $frag) {
    foreach (array('default' => false, 'legacy' => true) as $mode => $legacy) {
        echo "$label $mode: ", checkWsu(withUri('#' . $frag), $legacy, true), "\n";
    }
}

/* A fragment equal to another element's Id resolves to that element only. */
echo 'other element: ', checkWsu(withUri("#x'y"), false, true), "\n";

/* Without an Id attribute name for the namespace the reference does not resolve. */
$dsig = new XMLSecurityDSig();
$dsig->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);
$dsig->locateSignature($doc);
$dsig->canonicalizeSignedInfo();
echo 'no idKeys: ';
try {
    echo $dsig->validateReference() ? "valid\n" : "invalid\n";
} catch (Exception $e) {
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
URI: #a'"b
verify idNS default: verified a'"b
verify idNS legacy: verified a'"b
verify document binding default: verified a'"b
verify document binding legacy: verified a'"b
double quote only default: Reference URI does not identify a node
double quote only legacy: Reference URI does not identify a node
single quote only default: Reference URI does not identify a node
single quote only legacy: Reference URI does not identify a node
extra double quote default: Reference URI does not identify a node
extra double quote legacy: Reference URI does not identify a node
extra single quote default: Reference URI does not identify a node
extra single quote legacy: Reference URI does not identify a node
no quotes default: Reference URI does not identify a node
no quotes legacy: Reference URI does not identify a node
other element: Reference validation failed
no idKeys: Reference URI does not identify a node
