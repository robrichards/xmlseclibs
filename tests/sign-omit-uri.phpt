--TEST--
omit_uri references: document and document element round trip; nested elements are rejected
--DESCRIPTION--
A Reference without a URI is resolved by the verifier as the whole document, so
only a DOMDocument (or its document element) can be signed with omit_uri.
A nested element throws before any Reference is added. Changing a processing
instruction before the root fails reference validation, which shows the digest
covers the whole document. An omitted URI and an explicit URI="" stay distinct,
and a nested element still works by ID. A transform failure removes the
Reference being built and leaves earlier References in place.
low:ref-fail means locateSignature, canonicalizeSignedInfo, and verify()
succeeded and validateReference() failed.
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const SRC = "<?xml version=\"1.0\"?>\n<root><item><a>v</a></item><b/></root>";
const SRC_PI = "<?xml version=\"1.0\"?>\n<?before-root data?>\n<root><item><a>v</a></item><b/></root>";

function publicKey() {
	$k = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
	$k->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
	return $k;
}
function privateKey() {
	$k = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
	$k->loadKey(dirname(__FILE__) . '/privkey.pem', true);
	return $k;
}
function references($dsig) {
	$xp = new DOMXPath($dsig->sigNode->ownerDocument);
	$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
	return $xp->query('./ds:SignedInfo/ds:Reference', $dsig->sigNode);
}
function newSig() {
	$dsig = new XMLSecurityDSig();
	$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
	return $dsig;
}
function uriAttr($dsig) {
	$ref = references($dsig)->item(0);
	return $ref->hasAttribute('URI') ? 'URI="' . $ref->getAttribute('URI') . '"' : 'no URI attribute';
}
function digestCount($ref) {
	return $ref->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'DigestValue')->length;
}
function paths($xml) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	try {
		$nodes = (new XMLSecurityDSig())->verifyDocument(publicKey(), $doc);
		$docResult = (is_array($nodes) && count($nodes) === 1) ? 'ok' : 'bad-count';
	} catch (Exception $e) {
		$docResult = ($e->getMessage() === 'Reference validation failed') ? 'ref-fail' : ('fail:' . $e->getMessage());
	}

	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$d = new XMLSecurityDSig();
	if (! $d->locateSignature($doc)) {
		return 'doc:' . $docResult . ' low:noloc';
	}
	if ($d->canonicalizeSignedInfo() === null) {
		return 'doc:' . $docResult . ' low:noc14n';
	}
	$ref = 'ok';
	try {
		if ($d->validateReference() !== true) {
			$ref = 'ref-fail';
		}
	} catch (Exception $e) {
		$ref = ($e->getMessage() === 'Reference validation failed') ? 'ref-fail' : ('fail:' . $e->getMessage());
	}
	try {
		$sig = ($d->verify(publicKey()) === 1);
	} catch (Exception $e) {
		$sig = false;
	}
	if ($ref === 'ok' && $sig) {
		$low = 'ok';
	} elseif ($ref === 'ref-fail' && $sig) {
		$low = 'ref-fail';
	} else {
		$low = $ref . '/' . ($sig ? 'sig-ok' : 'sig-fail');
	}
	return 'doc:' . $docResult . ' low:' . $low;
}
function signedXml($node, $transforms, $options) {
	$doc = ($node instanceof DOMDocument) ? $node : $node->ownerDocument;
	$dsig = newSig();
	$dsig->addReference($node, XMLSecurityDSig::SHA256, $transforms, $options);
	$dsig->sign(privateKey());
	$dsig->appendSignature($doc->documentElement);
	return array($dsig, $doc->saveXML());
}

$transforms = array(XMLSecurityDSig::ENVELOPED, XMLSecurityDSig::EXC_C14N);

$doc = new DOMDocument();
$doc->loadXML(SRC);
list($dsig, $xml) = signedXml($doc, $transforms, array('omit_uri' => true));
echo "document omit_uri: ", uriAttr($dsig), ' ', paths($xml), "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC);
list($dsig, $xml) = signedXml($doc->documentElement, $transforms, array('omit_uri' => true));
echo "document element omit_uri (plain): ", uriAttr($dsig), ' ', paths($xml), "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC_PI);
list($dsig, $xml) = signedXml($doc->documentElement, $transforms, array('omit_uri' => true));
echo "document element omit_uri (leading PI): ", uriAttr($dsig), ' ', paths($xml), "\n";
echo "document element omit_uri (leading PI changed): ", paths(str_replace('before-root', 'edited-pi', $xml)), "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC);
list($dsig, $xml) = signedXml($doc, $transforms, array('force_uri' => true));
echo "document force_uri: ", uriAttr($dsig), ' ', paths($xml), "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC);
$dsig = newSig();
$dsig->addReference($doc, XMLSecurityDSig::SHA256, $transforms, array('force_uri' => true, 'omit_uri' => true));
echo "document force_uri+omit_uri: ", uriAttr($dsig), "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC);
$item = $doc->getElementsByTagName('item')->item(0);
$dsig = newSig();
try {
	$dsig->addReference($item, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::EXC_C14N), array('omit_uri' => true));
	echo "nested omit_uri: no exception\n";
} catch (Exception $e) {
	echo "nested omit_uri: ", $e->getMessage(), "\n";
}
echo "references left: ", references($dsig)->length, "; Id attribute added to element: ", $item->hasAttribute('Id') ? 'yes' : 'no', "\n";

$doc = new DOMDocument();
$doc->loadXML(SRC);
$dsig = newSig();
try {
	$dsig->addReferenceList(
		array($doc, $doc->getElementsByTagName('item')->item(0)),
		XMLSecurityDSig::SHA256,
		array(XMLSecurityDSig::EXC_C14N),
		array('omit_uri' => true)
	);
	echo "list: no exception\n";
} catch (Exception $e) {
	echo "list: exception after ", references($dsig)->length, " reference(s); first has DigestValue: ",
		digestCount(references($dsig)->item(0)), "\n";
}

$doc = new DOMDocument();
$doc->loadXML(SRC);
$dsig = newSig();
$dsig->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::EXC_C14N), array('omit_uri' => true));
try {
	$dsig->addReference($doc, XMLSecurityDSig::SHA256, array('http://example.test/unsupported-transform'), array('omit_uri' => true));
	echo "transform after existing: no exception\n";
} catch (Exception $e) {
	echo "transform after existing: ", $e->getMessage(),
		"; references left: ", references($dsig)->length,
		"; first DigestValue: ", digestCount(references($dsig)->item(0)), "\n";
}

$doc = new DOMDocument();
$doc->loadXML(SRC);
$dsig = newSig();
try {
	$dsig->addReference($doc, XMLSecurityDSig::SHA256, array('http://example.test/unsupported-transform'));
	echo "unsupported transform: no exception\n";
} catch (Exception $e) {
	echo "unsupported transform: ", $e->getMessage(), "; references left: ", references($dsig)->length, "\n";
}

$doc = new DOMDocument();
$doc->loadXML(SRC);
$item = $doc->getElementsByTagName('item')->item(0);
list($dsig, $xml) = signedXml($item, array(XMLSecurityDSig::EXC_C14N), null);
$uri = references($dsig)->item(0)->getAttribute('URI');
echo "nested by ID: URI starts with #: ", (isset($uri[0]) && $uri[0] === '#') ? 'yes' : 'no', ' ', paths($xml), "\n";
?>
--EXPECTF--
document omit_uri: no URI attribute doc:ok low:ok
document element omit_uri (plain): no URI attribute doc:ok low:ok
document element omit_uri (leading PI): no URI attribute doc:ok low:ok
document element omit_uri (leading PI changed): doc:ref-fail low:ref-fail
document force_uri: URI="" doc:ok low:ok
document force_uri+omit_uri: no URI attribute
nested omit_uri: omit_uri is only supported for a DOMDocument or its document element; a nested element must be referenced by URI
references left: 0; Id attribute added to element: no
list: exception after 1 reference(s); first has DigestValue: 1
transform after existing: Transform algorithm is not supported: 'http://example.test/unsupported-transform'; references left: 1; first DigestValue: 1
unsupported transform: Transform algorithm is not supported: 'http://example.test/unsupported-transform'; references left: 0
nested by ID: URI starts with #: yes doc:ok low:ok
