--TEST--
WithComments reference digests match verification for every supported reference form
--DESCRIPTION--
URI="", an omitted URI, and URI="#id" are dereferenced without comments, so a
WithComments canonicalization transform sees no comments on either side. The
Transform Algorithm on the Reference stays the one that was requested.
Signing XML that contains a comment and element text inside the referenced
content must verify, still verify after only the comment changes, and fail
reference validation after only that element text changes. Each check uses
verifyDocument() and the low-level path (locateSignature, canonicalizeSignedInfo,
validateReference, verify). low:ref-fail means the signature still verifies
and reference validation fails.
A transform-level check calls processTransforms with includeCommentNodes=true
and shows that WithComments still preserves comments when asked to.
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const SRC = "<?xml version=\"1.0\"?>\n<root><item><!-- note-comment --><a>payload-text</a></item><b/></root>";

function publicKey() {
	$k = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
	$k->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
	return $k;
}

function sign($form, $c14n) {
	$doc = new DOMDocument();
	$doc->loadXML(SRC);
	$dsig = new XMLSecurityDSig();
	$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
	if ($form === 'nested') {
		$node = $doc->getElementsByTagName('item')->item(0);
		$transforms = array($c14n);
		$options = null;
	} elseif ($form === 'omit') {
		$node = $doc;
		$transforms = array(XMLSecurityDSig::ENVELOPED, $c14n);
		$options = array('omit_uri' => true);
	} else {
		$node = $doc;
		$transforms = array(XMLSecurityDSig::ENVELOPED, $c14n);
		$options = array('force_uri' => true);
	}
	$dsig->addReference($node, XMLSecurityDSig::SHA256, $transforms, $options);
	$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
	$key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
	$dsig->sign($key);
	$dsig->appendSignature($doc->documentElement);
	return $doc->saveXML();
}

function referenceNode($xml) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$xp = new DOMXPath($doc);
	$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
	$ref = $xp->query('//ds:SignedInfo/ds:Reference')->item(0);
	return array($doc, $xp, $ref);
}

function uriForm($xml) {
	list(, , $ref) = referenceNode($xml);
	if (! $ref->hasAttribute('URI')) {
		return 'no-uri';
	}
	$uri = $ref->getAttribute('URI');
	if ($uri === '') {
		return 'uri-empty';
	}
	if (isset($uri[0]) && $uri[0] === '#' && strlen($uri) > 1) {
		return 'uri-id';
	}
	return 'uri-other';
}

function c14nAlgorithm($xml) {
	list(, $xp) = referenceNode($xml);
	$nodes = $xp->query('//ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform');
	$alg = '';
	foreach ($nodes as $node) {
		$algorithm = $node->getAttribute('Algorithm');
		if ($algorithm !== XMLSecurityDSig::ENVELOPED) {
			$alg = $algorithm;
		}
	}
	return $alg;
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

function canonicalIncludingComments($xml) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$d = new XMLSecurityDSig();
	$d->locateSignature($doc);
	$xp = new DOMXPath($doc);
	$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
	$ref = $xp->query('.//ds:Reference', $d->sigNode)->item(0);
	return $d->processTransforms($ref, $doc->getElementsByTagName('item')->item(0), true);
}

$forms = array(
	'URI="" enveloped' => array('empty', 'uri-empty'),
	'omit_uri document' => array('omit', 'no-uri'),
	'#id nested' => array('nested', 'uri-id'),
);
$transforms = array(
	'C14N' => XMLSecurityDSig::C14N,
	'C14N_COMMENTS' => XMLSecurityDSig::C14N_COMMENTS,
	'EXC_C14N' => XMLSecurityDSig::EXC_C14N,
	'EXC_C14N_COMMENTS' => XMLSecurityDSig::EXC_C14N_COMMENTS,
);

foreach ($forms as $fname => $form) {
	foreach ($transforms as $tname => $t) {
		$xml = sign($form[0], $t);
		$formOk = (uriForm($xml) === $form[1]) ? $form[1] : ('DIFF:' . uriForm($xml));
		$algOk = (c14nAlgorithm($xml) === $t) ? 'match' : ('DIFF:' . c14nAlgorithm($xml));
		$original = paths($xml);
		$comment = paths(str_replace('note-comment', 'edited-comment', $xml));
		$text = paths(str_replace('payload-text', 'payload-edited', $xml));
		echo "$fname | $tname | form=$formOk alg=$algOk | original=$original | comment=$comment | text=$text\n";
	}
}

foreach ($transforms as $tname => $t) {
	$xml = sign('nested', $t);
	$edited = str_replace('note-comment', 'edited-comment', $xml);
	$changes = canonicalIncludingComments($xml) !== canonicalIncludingComments($edited);
	echo "transform-level | $tname | includeCommentNodes=true comment-changes-data=", $changes ? 'yes' : 'no', "\n";
}
?>
--EXPECTF--
URI="" enveloped | C14N | form=uri-empty alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
URI="" enveloped | C14N_COMMENTS | form=uri-empty alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
URI="" enveloped | EXC_C14N | form=uri-empty alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
URI="" enveloped | EXC_C14N_COMMENTS | form=uri-empty alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
omit_uri document | C14N | form=no-uri alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
omit_uri document | C14N_COMMENTS | form=no-uri alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
omit_uri document | EXC_C14N | form=no-uri alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
omit_uri document | EXC_C14N_COMMENTS | form=no-uri alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
#id nested | C14N | form=uri-id alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
#id nested | C14N_COMMENTS | form=uri-id alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
#id nested | EXC_C14N | form=uri-id alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
#id nested | EXC_C14N_COMMENTS | form=uri-id alg=match | original=doc:ok low:ok | comment=doc:ok low:ok | text=doc:ref-fail low:ref-fail
transform-level | C14N | includeCommentNodes=true comment-changes-data=no
transform-level | C14N_COMMENTS | includeCommentNodes=true comment-changes-data=yes
transform-level | EXC_C14N | includeCommentNodes=true comment-changes-data=no
transform-level | EXC_C14N_COMMENTS | includeCommentNodes=true comment-changes-data=yes
