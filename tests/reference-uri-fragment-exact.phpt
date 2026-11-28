--TEST--
Reference URI fragments are compared exactly to ID attribute values
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\Utils\XPath;

function signDoc($xml, $idName = 'Id')
{
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    foreach ($doc->documentElement->childNodes as $child) {
        if ($child instanceof DOMElement) {
            $dsig->addReference(
                $child,
                XMLSecurityDSig::SHA256,
                array(XMLSecurityDSig::EXC_C14N),
                array('id_name' => $idName, 'overwrite' => false)
            );
        }
    }
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    $dsig->sign($key);
    $dsig->appendSignature($doc->documentElement);
    return $doc;
}

function verifyDoc($doc, $legacy = false, $idKeys = array())
{
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    $dsig->idKeys = $idKeys;
    $dsig->allowedSignatureAlgorithms = array(XMLSecurityKey::RSA_SHA256);
    $dsig->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);
    $pub = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $pub->loadKey(dirname(__FILE__) . '/mycert.pem', true);
    try {
        $nodes = $dsig->verifyDocument($pub, $doc);
        return 'verified ' . count($nodes);
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

/* Reference processing only, with the signature value left out of it. */
function checkReferences($doc, $legacy = false)
{
    $dsig = new XMLSecurityDSig();
    if ($legacy) {
        $dsig->enableLegacyMode();
    }
    $dsig->allowedDigestAlgorithms = array(XMLSecurityDSig::SHA256);
    $dsig->locateSignature($doc);
    $dsig->canonicalizeSignedInfo();
    try {
        return $dsig->validateReference() ? 'valid' : 'invalid';
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

function setFirstReferenceUri($doc, $uri)
{
    $refs = $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Reference');
    $refs->item(0)->setAttribute('URI', $uri);
}

/* Literals evaluate to exactly the input. */
$xp = new DOMXPath(new DOMDocument());
foreach (array('abc', 'a"b', "a'b", "a'\"b", "'\"", "\"'", '""', "''\"\"x") as $v) {
    echo 'literal ', $xp->evaluate('string(' . XPath::quoteValue($v) . ')') === $v ? 'exact' : 'DIFFERENT', "\n";
}

/* A plain Id resolves and verifies, including through the signing path. */
$plain = '<Root><A Id="ab">one</A><B Id="other">two</B></Root>';
echo 'plain: ', verifyDoc(signDoc($plain)), "\n";
echo 'plain legacy: ', verifyDoc(signDoc($plain), true), "\n";

/* Ids holding quote characters are referenced and verify as written. */
$quoted = '<Root><A Id="a&quot;b">one</A><B Id="a\'b">two</B>'
    . '<C Id="a\'&quot;b">three</C></Root>';
echo 'quoted: ', verifyDoc(signDoc($quoted)), "\n";
echo 'quoted legacy: ', verifyDoc(signDoc($quoted), true), "\n";
echo 'quoted idKeys: ', verifyDoc(signDoc(str_replace('Id=', 'ID=', $quoted), 'ID'), false, array('ID')), "\n";

/* The unmodified references pass the same check. */
echo 'unmodified: ', checkReferences(signDoc($quoted)), "\n";

/* A fragment with quote characters does not match an Id without them. */
foreach (array('a"b', "a'b", "a'\"b", "\"ab", "ab'") as $frag) {
    $doc = signDoc($plain);
    setFirstReferenceUri($doc, '#' . $frag);
    echo 'no match ', $frag, ': ', checkReferences($doc), "\n";
    $doc = signDoc($plain);
    setFirstReferenceUri($doc, '#' . $frag);
    echo 'no match legacy ', $frag, ': ', checkReferences($doc, true), "\n";
}

/* A quoted Id is matched only by its exact value. */
$doc = signDoc($quoted);
setFirstReferenceUri($doc, '#ab');
echo 'different value: ', checkReferences($doc), "\n";

/* The xpointer form is not interpreted; the fragment is an ordinary value. */
$doc = signDoc($plain);
setFirstReferenceUri($doc, "#xpointer(id('ab'))");
echo 'xpointer: ', checkReferences($doc), "\n";
?>
--EXPECT--
literal exact
literal exact
literal exact
literal exact
literal exact
literal exact
literal exact
literal exact
plain: verified 2
plain legacy: verified 2
quoted: verified 3
quoted legacy: verified 3
quoted idKeys: verified 3
unmodified: valid
no match a"b: Reference URI does not identify a node
no match legacy a"b: Reference URI does not identify a node
no match a'b: Reference URI does not identify a node
no match legacy a'b: Reference URI does not identify a node
no match a'"b: Reference URI does not identify a node
no match legacy a'"b: Reference URI does not identify a node
no match "ab: Reference URI does not identify a node
no match legacy "ab: Reference URI does not identify a node
no match ab': Reference URI does not identify a node
no match legacy ab': Reference URI does not identify a node
different value: Reference URI does not identify a node
xpointer: Reference URI does not identify a node
