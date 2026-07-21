--TEST--
Decrypted XML containing a DOCTYPE is rejected (entity-expansion defense)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function decryptPayload($payload) {
    $symKey = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
    $symKey->generateSessionKey();
    $cipher = base64_encode($symKey->encryptData($payload));

    $doc = new DOMDocument();
    $doc->loadXML(
        '<Root xmlns="urn:e">'
        . '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" '
        . 'Type="http://www.w3.org/2001/04/xmlenc#Element">'
        . '<xenc:CipherData><xenc:CipherValue>'.$cipher.'</xenc:CipherValue></xenc:CipherData>'
        . '</xenc:EncryptedData></Root>'
    );

    $objenc = new XMLSecEnc();
    $encData = $objenc->locateEncryptedData($doc);
    $objenc->setNode($encData);
    $objenc->type = $encData->getAttribute('Type');
    return $objenc->decryptNode($symKey, true);
}

/* 1. Malicious payload with a DOCTYPE is refused. */
try {
    decryptPayload('<!DOCTYPE foo [<!ENTITY x "y">]><foo>bar</foo>');
    print "DOCTYPE: unexpected success\n";
} catch (Exception $e) {
    print "DOCTYPE: ".$e->getMessage()."\n";
}

/* 2. Ordinary payload still decrypts. */
try {
    $node = decryptPayload('<foo>bar</foo>');
    print "CLEAN: ".($node instanceof DOMNode ? "ok" : "fail")."\n";
} catch (Exception $e) {
    print "CLEAN: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
DOCTYPE: Decrypted XML must not contain a DOCTYPE
CLEAN: ok
