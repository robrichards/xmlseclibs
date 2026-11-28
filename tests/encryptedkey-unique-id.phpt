--TEST--
RetrievalMethod resolves an EncryptedKey by same-document Id only when exactly one XML Encryption EncryptedKey carries it
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const T_XENC = XMLSecEnc::XMLENCNS;
const T_DS = XMLSecurityDSig::XMLDSIGNS;

/* Standalone xenc:EncryptedKey (RSA-OAEP) wrapping $sym for tests/privkey.pem. */
function wrapKey(XMLSecurityKey $sym) {
    $public = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
    $public->loadKey(__DIR__ . '/mycert.pem', true, true);
    $scratch = new DOMDocument();
    $scratch->loadXML('<r>x</r>');
    $enc = new XMLSecEnc();
    $enc->setNode($scratch->documentElement);
    $enc->type = XMLSecEnc::Element;
    $enc->encryptKey($public, $sym);
    $enc->encryptNode($sym);
    $source = $scratch->getElementsByTagNameNS(T_XENC, 'EncryptedKey')->item(0);
    $copy = new DOMDocument();
    $copy->loadXML('<xenc:EncryptedKey xmlns:xenc="' . T_XENC . '" xmlns:ds="' . T_DS . '"/>');
    foreach ($source->childNodes as $child) {
        $copy->documentElement->appendChild($copy->importNode($child, true));
    }
    return $copy->saveXML($copy->documentElement);
}

/* GOOD wraps the key that protects the data; OTHER wraps a different key (valid transport, wrong key). */
$good = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$good->generateSessionKey();
$other = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
$other->generateSessionKey();
$scratch = new DOMDocument();
$scratch->loadXML('<root>payload</root>');
$enc = new XMLSecEnc();
$enc->setNode($scratch->documentElement);
$enc->type = XMLSecEnc::Element;
$enc->encryptNode($good);
$cipher = $scratch->getElementsByTagNameNS(T_XENC, 'CipherValue')->item(0)->textContent;

$GOOD = wrapKey($good);
$OTHER = wrapKey($other);
/* Candidates that throw a different exception if they are processed at all. */
$NOTRANSPORT = '<xenc:EncryptedKey xmlns:xenc="' . T_XENC . '"><xenc:EncryptionMethod Algorithm="' . XMLSecurityKey::AES128_CBC . '"/>'
    . '<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
$DANGLING = '<xenc:EncryptedKey xmlns:xenc="' . T_XENC . '" xmlns:ds="' . T_DS . '"><xenc:EncryptionMethod Algorithm="' . XMLSecurityKey::RSA_OAEP_MGF1P . '"/>'
    . '<ds:KeyInfo><ds:RetrievalMethod URI="#nowhere" Type="' . T_XENC . 'EncryptedKey"/></ds:KeyInfo>'
    . '<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';

function withAttrs($xml, $attrs) {
    return preg_replace('/^<xenc:EncryptedKey/', '<xenc:EncryptedKey ' . $attrs, $xml, 1);
}

function retrieval($uri, $type = null) {
    $type = $type === null ? T_XENC . 'EncryptedKey' : $type;
    return '<ds:RetrievalMethod URI="' . $uri . '" Type="' . $type . '"/>';
}

function document($keyInfo, $siblings) {
    global $cipher;
    return '<Root xmlns:xenc="' . T_XENC . '" xmlns:ds="' . T_DS . '" xmlns:o="urn:other" xmlns:wsu="urn:wsu">'
        . '<xenc:EncryptedData Type="' . T_XENC . 'Element">'
        . '<xenc:EncryptionMethod Algorithm="' . XMLSecurityKey::AES256_GCM . '"/>'
        . '<ds:KeyInfo>' . $keyInfo . '</ds:KeyInfo>'
        . '<xenc:CipherData><xenc:CipherValue>' . $cipher . '</xenc:CipherValue></xenc:CipherData>'
        . '</xenc:EncryptedData>' . $siblings . '</Root>';
}

/* Normal lookup path: locateKey(), locateKeyInfo(), then decryptKey() and decryptNode(). */
function resolveAndDecrypt($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    $dec->setNode($dec->locateEncryptedData($doc));
    $dec->type = XMLSecEnc::Element;
    $dataKey = $dec->locateKey();
    $transport = $dec->locateKeyInfo($dataKey);
    if ($transport === $dataKey) {
        return 'base key returned (nothing resolved)';
    }
    if (! $transport->isEncrypted) {
        return 'not an encrypted key';
    }
    $transport->loadKey(__DIR__ . '/privkey.pem', true);
    $dataKey->loadKey($transport->encryptedCtx->decryptKey($transport));
    $dec->decryptNode($dataKey, true);
    $result = $doc->getElementsByTagName('root')->item(0);
    return $result !== null && $result->textContent === 'payload' ? 'decrypted' : 'unexpected result';
}

function attempt($name, $xml) {
    try {
        echo "$name: " . resolveAndDecrypt($xml) . "\n";
    } catch (Exception $e) {
        echo "$name: " . get_class($e) . ': ' . $e->getMessage() . "\n";
    }
}

$k = 'Id="k"';

echo "-- unique match --\n";
attempt('unique', document(retrieval('#k'), withAttrs($GOOD, $k)));
attempt('unique, nested in another element', document(retrieval('#k'), '<Wrap>' . withAttrs($GOOD, $k) . '</Wrap>'));
attempt('unique, before the EncryptedData holder', '<Root xmlns:xenc="' . T_XENC . '" xmlns:ds="' . T_DS . '">'
    . withAttrs($GOOD, $k) . substr(document(retrieval('#k'), ''), strlen('<Root xmlns:xenc="' . T_XENC . '" xmlns:ds="' . T_DS . '" xmlns:o="urn:other" xmlns:wsu="urn:wsu">')));

echo "-- ambiguous: the same exception in both orders, before any candidate is processed --\n";
attempt('GOOD, OTHER', document(retrieval('#k'), withAttrs($GOOD, $k) . withAttrs($OTHER, $k)));
attempt('OTHER, GOOD', document(retrieval('#k'), withAttrs($OTHER, $k) . withAttrs($GOOD, $k)));
attempt('GOOD, GOOD', document(retrieval('#k'), withAttrs($GOOD, $k) . withAttrs($GOOD, $k)));
attempt('NOTRANSPORT, GOOD', document(retrieval('#k'), withAttrs($NOTRANSPORT, $k) . withAttrs($GOOD, $k)));
attempt('GOOD, NOTRANSPORT', document(retrieval('#k'), withAttrs($GOOD, $k) . withAttrs($NOTRANSPORT, $k)));
attempt('DANGLING, GOOD', document(retrieval('#k'), withAttrs($DANGLING, $k) . withAttrs($GOOD, $k)));
attempt('GOOD, DANGLING', document(retrieval('#k'), withAttrs($GOOD, $k) . withAttrs($DANGLING, $k)));
attempt('ambiguous across containers', document(retrieval('#k'), '<A>' . withAttrs($GOOD, $k) . '</A><B>' . withAttrs($OTHER, $k) . '</B>'));

echo "-- ambiguous Id reached through an EncryptedKey's own KeyInfo --\n";
$chained = withAttrs(str_replace('<xenc:CipherData>', '<ds:KeyInfo>' . retrieval('#dup') . '</ds:KeyInfo><xenc:CipherData>', $GOOD), 'Id="top"');
attempt('chained', document(retrieval('#top'), $chained . withAttrs($GOOD, 'Id="dup"') . withAttrs($OTHER, 'Id="dup"')));

echo "-- only xenc:EncryptedKey elements with that exact Id count --\n";
$foreign = str_replace(array('<xenc:EncryptedKey', '</xenc:EncryptedKey>'), array('<o:EncryptedKey', '</o:EncryptedKey>'), withAttrs($OTHER, $k));
$otherNs = str_replace(T_XENC, 'urn:not-xenc', withAttrs($OTHER, $k));
attempt('non-EncryptedKey element with the Id', document(retrieval('#k'), '<Other Id="k"/>' . withAttrs($GOOD, $k)));
attempt('Id on a ds:Reference-like element', document(retrieval('#k'), '<ds:Reference Id="k"/>' . withAttrs($GOOD, $k)));
attempt('foreign-prefix o:EncryptedKey, then GOOD', document(retrieval('#k'), $foreign . withAttrs($GOOD, $k)));
attempt('GOOD, then foreign-prefix o:EncryptedKey', document(retrieval('#k'), withAttrs($GOOD, $k) . $foreign));
attempt('other-namespace EncryptedKey, then GOOD', document(retrieval('#k'), $otherNs . withAttrs($GOOD, $k)));
attempt('GOOD, then other-namespace EncryptedKey', document(retrieval('#k'), withAttrs($GOOD, $k) . $otherNs));
foreach (array('ID="k"', 'id="k"', 'wsu:Id="k"', 'xml:id="k"') as $attr) {
    attempt("other attribute $attr, then GOOD", document(retrieval('#k'), withAttrs($OTHER, $attr) . withAttrs($GOOD, $k)));
}
attempt('different Id value, then GOOD', document(retrieval('#k'), withAttrs($OTHER, 'Id="K"') . withAttrs($GOOD, $k)));

echo "-- unresolved and unsupported references keep their behavior --\n";
attempt('missing Id', document(retrieval('#missing'), withAttrs($GOOD, $k)));
attempt('only a foreign-prefix element has the Id', document(retrieval('#k'), $foreign));
attempt('only an attribute ID=k', document(retrieval('#k'), withAttrs($GOOD, 'ID="k"')));
attempt('empty URI', document(retrieval(''), withAttrs($GOOD, $k)));
attempt('external URI', document(retrieval('http://example.org/k#k'), withAttrs($GOOD, $k)));
attempt('relative URI', document(retrieval('k'), withAttrs($GOOD, $k)));
attempt('other Type', document(retrieval('#k', T_XENC . 'EncryptedData'), withAttrs($GOOD, $k)));
attempt('no Type', document('<ds:RetrievalMethod URI="#k"/>', withAttrs($GOOD, $k)));
attempt('no EncryptedKey at all with the Id', document(retrieval('#k'), ''));
attempt('self-referencing key', document(retrieval('#k'), withAttrs(str_replace('<xenc:CipherData>', '<ds:KeyInfo>' . retrieval('#k') . '</ds:KeyInfo><xenc:CipherData>', $GOOD), $k)));

echo "-- embedded EncryptedKey --\n";
attempt('embedded', document($GOOD, ''));
attempt('embedded, duplicate Id elsewhere is not consulted', document($GOOD, withAttrs($OTHER, $k) . withAttrs($OTHER, $k)));
attempt('embedded foreign-prefix element is not key material', document(str_replace(array('<xenc:EncryptedKey', '</xenc:EncryptedKey>'), array('<o:EncryptedKey', '</o:EncryptedKey>'), $GOOD), ''));
?>
--EXPECTF--
-- unique match --
unique: decrypted
unique, nested in another element: decrypted
unique, before the EncryptedData holder: decrypted
-- ambiguous: the same exception in both orders, before any candidate is processed --
GOOD, OTHER: Exception: Multiple EncryptedKey elements with @Id='k'.
OTHER, GOOD: Exception: Multiple EncryptedKey elements with @Id='k'.
GOOD, GOOD: Exception: Multiple EncryptedKey elements with @Id='k'.
NOTRANSPORT, GOOD: Exception: Multiple EncryptedKey elements with @Id='k'.
GOOD, NOTRANSPORT: Exception: Multiple EncryptedKey elements with @Id='k'.
DANGLING, GOOD: Exception: Multiple EncryptedKey elements with @Id='k'.
GOOD, DANGLING: Exception: Multiple EncryptedKey elements with @Id='k'.
ambiguous across containers: Exception: Multiple EncryptedKey elements with @Id='k'.
-- ambiguous Id reached through an EncryptedKey's own KeyInfo --
chained: Exception: Multiple EncryptedKey elements with @Id='dup'.
-- only xenc:EncryptedKey elements with that exact Id count --
non-EncryptedKey element with the Id: decrypted
Id on a ds:Reference-like element: decrypted
foreign-prefix o:EncryptedKey, then GOOD: decrypted
GOOD, then foreign-prefix o:EncryptedKey: decrypted
other-namespace EncryptedKey, then GOOD: decrypted
GOOD, then other-namespace EncryptedKey: decrypted
other attribute ID="k", then GOOD: decrypted
other attribute id="k", then GOOD: decrypted
other attribute wsu:Id="k", then GOOD: decrypted
other attribute xml:id="k", then GOOD: decrypted
different Id value, then GOOD: decrypted
-- unresolved and unsupported references keep their behavior --
missing Id: Exception: Unable to locate EncryptedKey with @Id='missing'.
only a foreign-prefix element has the Id: Exception: Unable to locate EncryptedKey with @Id='k'.
only an attribute ID=k: Exception: Unable to locate EncryptedKey with @Id='k'.
empty URI: base key returned (nothing resolved)
external URI: base key returned (nothing resolved)
relative URI: base key returned (nothing resolved)
other Type: base key returned (nothing resolved)
no Type: base key returned (nothing resolved)
no EncryptedKey at all with the Id: Exception: Unable to locate EncryptedKey with @Id='k'.
self-referencing key: Exception: EncryptedKey reference chain is too deep
-- embedded EncryptedKey --
embedded: decrypted
embedded, duplicate Id elsewhere is not consulted: decrypted
embedded foreign-prefix element is not key material: base key returned (nothing resolved)
