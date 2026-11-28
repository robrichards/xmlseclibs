--TEST--
A failed Reference is removed and any ID it wrote is put back
--DESCRIPTION--
addReference() appends a Reference before it finishes the ID attribute and
the transforms. A DOMException from an invalid id name or prefix, and a
TypeError from an array transform without a query, are rethrown unchanged.
The Reference being built is removed. A previously completed Reference stays
byte for byte. An ID that was absent stays absent. An ID that was overwritten
keeps its text, qualified name, namespace and prefix, including text
that contains "&", "<" and a quote. A prefix binding added for a
generated ID is removed with it, including when that prefix was already
bound to a different namespace. A binding already on the element or
an ancestor stays. An ID only read (overwrite false) is left untouched.
The signature still verifies. No PHP warning is emitted.
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
const TYPE_MSG = 'DOMElement::setAttribute(): Argument #2 ($value) must be of type string, array given';

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
function signedInfo($dsig) {
	$xp = new DOMXPath($dsig->sigNode->ownerDocument);
	$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
	return $xp->query('./ds:SignedInfo', $dsig->sigNode)->item(0);
}
function referenceCount($dsig) {
	$xp = new DOMXPath($dsig->sigNode->ownerDocument);
	$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
	return $xp->query('./ds:SignedInfo/ds:Reference', $dsig->sigNode)->length;
}
function attrState($el) {
	$parts = array();
	if ($el->attributes !== null) {
		foreach ($el->attributes as $attr) {
			$parts[] = $attr->nodeName
				. "\t" . ($attr->namespaceURI === null ? '' : $attr->namespaceURI)
				. "\t" . ($attr->prefix === null ? '' : $attr->prefix)
				. "\t" . $attr->value;
		}
	}
	sort($parts);
	return implode("\n", $parts);
}
function prepare($xml) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$dsig = new XMLSecurityDSig();
	$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
	$dsig->addReference(
		$doc->getElementsByTagName('good')->item(0),
		XMLSecurityDSig::SHA256,
		array(XMLSecurityDSig::EXC_C14N)
	);
	return array($doc, $dsig);
}
function verify($doc, $dsig) {
	$dsig->sign(privateKey());
	$dsig->appendSignature($doc->documentElement);
	$reloaded = new DOMDocument();
	$reloaded->loadXML($doc->saveXML());
	try {
		$nodes = (new XMLSecurityDSig())->verifyDocument(publicKey(), $reloaded);
	} catch (Exception $e) {
		return 'fail:' . $e->getMessage();
	}
	return (is_array($nodes) && count($nodes) === 1) ? 'ok' : 'bad-count';
}

$plain = '<?xml version="1.0"?><root xmlns:wsu="' . WSU . '"><good>stable</good><target>payload</target></root>';
$plainId = '<?xml version="1.0"?><root xmlns:wsu="' . WSU . '"><good>stable</good><target Id="keep-plain">payload</target></root>';
$nsId = '<?xml version="1.0"?><root xmlns:wsu="' . WSU . '"><good>stable</good><target wsu:Id="keep-ns">payload</target></root>';
$badTransform = array(array('algorithm' => XMLSecurityDSig::EXC_C14N));
$nsOptions = array(
	'prefix' => 'wsu',
	'prefix_ns' => WSU,
	'id_name' => 'Id',
);

$cases = array(
	array('dom-plain-absent', $plain, array(XMLSecurityDSig::EXC_C14N), array('id_name' => '1bad'), 'DOMException', 'Invalid Character Error'),
	array('dom-plain-existing', $plainId, array(XMLSecurityDSig::EXC_C14N), array('id_name' => '1bad'), 'DOMException', 'Invalid Character Error'),
	array('dom-ns-absent', $plain, array(XMLSecurityDSig::EXC_C14N), array('prefix' => 'wsu', 'id_name' => 'Id'), 'DOMException', 'Namespace Error'),
	array('dom-ns-existing', $nsId, array(XMLSecurityDSig::EXC_C14N), array('prefix' => 'wsu', 'id_name' => 'Id'), 'DOMException', 'Namespace Error'),
	array('type-plain-absent', $plain, $badTransform, null, 'TypeError', TYPE_MSG),
	array('type-plain-existing', $plainId, $badTransform, null, 'TypeError', TYPE_MSG),
	array('type-ns-absent', $plain, $badTransform, $nsOptions, 'TypeError', TYPE_MSG),
	array('type-ns-existing', $nsId, $badTransform, $nsOptions, 'TypeError', TYPE_MSG),
	array('type-plain-reuse', $plainId, $badTransform, array('overwrite' => false), 'TypeError', TYPE_MSG),
	array('type-ns-reuse', $nsId, $badTransform, array('overwrite' => false, 'prefix' => 'wsu', 'prefix_ns' => WSU, 'id_name' => 'Id'), 'TypeError', TYPE_MSG),
);

foreach ($cases as $case) {
	list($label, $xml, $transforms, $options, $expectClass, $expectMsg) = $case;
	list($doc, $dsig) = prepare($xml);
	$target = $doc->getElementsByTagName('target')->item(0);
	$beforeInfo = signedInfo($dsig)->C14N();
	$beforeAttrs = attrState($target);
	$gotClass = '';
	$gotMsg = '';
	try {
		$dsig->addReference($target, XMLSecurityDSig::SHA256, $transforms, $options);
		$gotClass = 'none';
	} catch (Throwable $e) {
		$gotClass = get_class($e);
		$gotMsg = $e->getMessage();
	}
	$sameInfo = (signedInfo($dsig)->C14N() === $beforeInfo) ? 'same' : 'DIFF';
	$sameAttrs = (attrState($target) === $beforeAttrs) ? 'same' : 'DIFF';
	$classOk = ($gotClass === $expectClass && $gotMsg === $expectMsg) ? 'ok' : ($gotClass . '|' . $gotMsg);
	echo $label, ': exception=', $classOk,
		' refs=', referenceCount($dsig),
		' signedinfo=', $sameInfo,
		' attrs=', $sameAttrs,
		' verify=', verify($doc, $dsig), "\n";
}

$entity = 'a &amp; b &lt; c &quot; d';
$entityPlain = '<?xml version="1.0"?><root><good>stable</good><target Id="' . $entity . '">payload</target></root>';
$entityWsu = '<?xml version="1.0"?><root xmlns:wsu="' . WSU . '"><good>stable</good><target wsu:Id="' . $entity . '">payload</target></root>';
$unbound = '<?xml version="1.0"?><root><good>stable</good><target>x</target></root>';
$boundElement = '<?xml version="1.0"?><root><good>stable</good><target xmlns:p="urn:p">x</target></root>';
$boundAncestor = '<?xml version="1.0"?><root xmlns:p="urn:p"><good>stable</good><target>x</target></root>';
$pOptions = array('prefix' => 'p', 'prefix_ns' => 'urn:p', 'id_name' => 'Id');
$wsuEntityOptions = array('prefix' => 'wsu', 'prefix_ns' => WSU, 'id_name' => 'Id');
$inheritedConflict = '<?xml version="1.0"?><r xmlns:p="urn:other"><good>stable</good><target>x</target></r>';
$localConflict = '<?xml version="1.0"?><r><good>stable</good><target xmlns:p="urn:other">x</target></r>';
$inheritedOverwrite = '<?xml version="1.0"?><r xmlns:p="urn:other" xmlns:q="urn:p"><good>stable</good><target q:Id="keep-q">x</target></r>';
$localOverwrite = '<?xml version="1.0"?><r><good>stable</good><target xmlns:p="urn:other" xmlns:q="urn:p" q:Id="keep-q">x</target></r>';

$textCases = array(
	array('entity-plain', $entityPlain, null),
	array('entity-wsu', $entityWsu, $wsuEntityOptions),
	array('prefix-unbound', $unbound, $pOptions),
	array('prefix-on-element', $boundElement, $pOptions),
	array('prefix-on-ancestor', $boundAncestor, $pOptions),
	array('prefix-inherited-conflict', $inheritedConflict, $pOptions),
	array('prefix-local-conflict', $localConflict, $pOptions),
	array('prefix-inherited-overwrite', $inheritedOverwrite, $pOptions),
	array('prefix-local-overwrite', $localOverwrite, $pOptions),
);

foreach ($textCases as $case) {
	list($label, $xml, $options) = $case;
	list($doc, $dsig) = prepare($xml);
	$target = $doc->getElementsByTagName('target')->item(0);
	$beforeInfo = signedInfo($dsig)->C14N();
	$beforeInc = $target->C14N(false, false);
	$beforeExc = $target->C14N(true, false);
	$warnings = array();
	set_error_handler(function ($severity, $message) use (&$warnings) {
		$warnings[] = $message;
		return true;
	});
	$gotClass = '';
	$gotMsg = '';
	try {
		$dsig->addReference($target, XMLSecurityDSig::SHA256, $badTransform, $options);
		$gotClass = 'none';
	} catch (Throwable $e) {
		$gotClass = get_class($e);
		$gotMsg = $e->getMessage();
	}
	restore_error_handler();
	$sameInfo = (signedInfo($dsig)->C14N() === $beforeInfo) ? 'same' : 'DIFF';
	$sameInc = ($target->C14N(false, false) === $beforeInc);
	$sameExc = ($target->C14N(true, false) === $beforeExc);
	if ($sameInc && $sameExc) {
		$sameC14n = 'same';
	} else {
		$sameC14n = 'DIFF inc-before=' . $beforeInc
			. ' inc-after=' . $target->C14N(false, false)
			. ' exc-before=' . $beforeExc
			. ' exc-after=' . $target->C14N(true, false);
	}
	$classOk = ($gotClass === 'TypeError' && $gotMsg === TYPE_MSG) ? 'ok' : ($gotClass . '|' . $gotMsg);
	echo $label, ': exception=', $classOk,
		' refs=', referenceCount($dsig),
		' signedinfo=', $sameInfo,
		' c14n=', $sameC14n,
		' warnings=', count($warnings),
		' verify=', verify($doc, $dsig), "\n";
}
?>
--EXPECTF--
dom-plain-absent: exception=ok refs=1 signedinfo=same attrs=same verify=ok
dom-plain-existing: exception=ok refs=1 signedinfo=same attrs=same verify=ok
dom-ns-absent: exception=ok refs=1 signedinfo=same attrs=same verify=ok
dom-ns-existing: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-plain-absent: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-plain-existing: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-ns-absent: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-ns-existing: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-plain-reuse: exception=ok refs=1 signedinfo=same attrs=same verify=ok
type-ns-reuse: exception=ok refs=1 signedinfo=same attrs=same verify=ok
entity-plain: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
entity-wsu: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-unbound: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-on-element: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-on-ancestor: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-inherited-conflict: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-local-conflict: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-inherited-overwrite: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
prefix-local-overwrite: exception=ok refs=1 signedinfo=same c14n=same warnings=0 verify=ok
