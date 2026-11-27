--TEST--
allowedDataAlgorithms is carried to the encryptedCtx of EncryptedKeys resolved via KeyInfo and the static helpers
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

const NS = 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
$data = array(XMLSecurityKey::AES256_GCM);

function ek($alg, $attrs = '', $keyInfo = '') {
    return '<xenc:EncryptedKey'.$attrs.'><xenc:EncryptionMethod Algorithm="'.$alg.'"/>'
        .($keyInfo !== '' ? '<ds:KeyInfo>'.$keyInfo.'</ds:KeyInfo>' : '')
        .'<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
}
function ed($keyInfo, $after = '') {
    return '<Root '.NS.'><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="'.XMLSecurityKey::AES256_GCM.'"/>'
        .'<ds:KeyInfo>'.$keyInfo.'</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>'
        .'</xenc:EncryptedData>'.$after.'</Root>';
}
function show($name, XMLSecurityKey $key, $expected) {
    $ctx = $key->encryptedCtx;
    echo "$name: ".($ctx->allowedDataAlgorithms === $expected ? 'propagated' : var_export($ctx->allowedDataAlgorithms, true))
        .' / '.$key->getAlgorithm()."\n";
}
function viaLocateKeyInfo($xml, $data) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dec = new XMLSecEnc();
    $dec->allowedDataAlgorithms = $data;
    $dec->setNode($dec->locateEncryptedData($doc));
    return $dec->locateKeyInfo($dec->locateKey());
}

/* locateKeyInfo(): embedded and RetrievalMethod. */
show('LOCATE_EMBEDDED', viaLocateKeyInfo(ed(ek(XMLSecurityKey::RSA_OAEP_MGF1P)), $data), $data);
show('LOCATE_RETRIEVAL', viaLocateKeyInfo(
    ed('<ds:RetrievalMethod URI="#k" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/>',
        str_replace('<xenc:EncryptedKey', '<xenc:EncryptedKey '.NS, ek(XMLSecurityKey::RSA_OAEP, ' Id="k"'))),
    $data
), $data);

/* Static helpers: explicit argument, omitted (DEFAULT_DATA_ALGORITHMS), explicit null, and staticLocateKeyInfo(). */
$doc = new DOMDocument();
$doc->loadXML('<Root '.NS.'>'.ek(XMLSecurityKey::RSA_OAEP, '', ek(XMLSecurityKey::RSA_OAEP_MGF1P)).'</Root>');
$outer = $doc->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
show('STATIC_FROM', XMLSecurityKey::fromEncryptedKeyElement($outer, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, $data), $data);
show('STATIC_FROM_OMITTED', XMLSecurityKey::fromEncryptedKeyElement($outer), XMLSecEnc::DEFAULT_DATA_ALGORITHMS);
show('STATIC_FROM_NULL', XMLSecurityKey::fromEncryptedKeyElement($outer, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, null), null);
$base = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP, array('type' => 'private'));
show('STATIC_LOCATE_NESTED', XMLSecEnc::staticLocateKeyInfo($base, $outer, 0, false, XMLSecEnc::DEFAULT_KEY_ALGORITHMS, $data), $data);
?>
--EXPECTF--
LOCATE_EMBEDDED: propagated / http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
LOCATE_RETRIEVAL: propagated / http://www.w3.org/2009/xmlenc11#rsa-oaep
STATIC_FROM: propagated / http://www.w3.org/2009/xmlenc11#rsa-oaep
STATIC_FROM_OMITTED: propagated / http://www.w3.org/2009/xmlenc11#rsa-oaep
STATIC_FROM_NULL: propagated / http://www.w3.org/2009/xmlenc11#rsa-oaep
STATIC_LOCATE_NESTED: propagated / http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
