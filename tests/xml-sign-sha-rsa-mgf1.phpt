--TEST--
Signatures with shaXXX-rsa-MGF1 algorithms
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('FILE_SIGNED_DOC', dirname(__FILE__) . '/xml-sign-sha-rsa-mgf1.xml');
define('FILE_BASIC_DOC', dirname(__FILE__) . '/basic-doc.xml');
define('FILE_KEY_PRIV', dirname(__FILE__) . '/privkey.pem');
define('FILE_KEY_PUB', dirname(__FILE__) . '/pubkey.pem');
define('FILE_CERT', dirname(__FILE__) . '/mycert.pem');

echo("Sign and verify basic-doc.xml ...\n\n");

function signAndVerify($digestAlgo, $signAlgo) {

    echo("Usign sign algo: ".$signAlgo." \n");

    // sign
    $doc = new DOMDocument();
    $doc->load(FILE_BASIC_DOC);
    $objKeyPriv = new XMLSecurityKey($signAlgo, array('type'=>'private'));
    $objKeyPriv->loadKey(FILE_KEY_PRIV, TRUE);
    $objDSig = new XMLSecurityDSig();
    $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $objDSig->addReference($doc, $digestAlgo, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));
    $objDSig->sign($objKeyPriv);
    $objDSig->add509Cert(FILE_CERT);
    $objDSig->appendSignature($doc->documentElement);

    // verify
    $objDSig = new XMLSecurityDSig();
    $objDSig->locateSignature($doc);
    $objDSig->canonicalizeSignedInfo();
    $objDSig->validateReference();
    // verify with certificate
    $objKeyPub = new XMLSecurityKey($signAlgo, array('type'=>'public'));
    $objKeyPub->loadKey(FILE_CERT, TRUE, TRUE);
    $verify = $objDSig->verify($objKeyPub);
    if ($verify !== 1) {
        echo("\tFailed to verify via cert\n");
    } else {
        echo("Successfully verified via cert\n");
    }
    // verify with pubkey
    $objKeyPub = new XMLSecurityKey($signAlgo, array('type'=>'public'));
    $objKeyPub->loadKey(FILE_KEY_PUB, TRUE, FALSE);
    $verify = $objDSig->verify($objKeyPub);
    if ($verify !== 1) {
        echo("\tFailed to verify via pubkey \n");
    } else {
        echo("Successfully verified via pubkey\n");
    }

    return;
}

$algos = [
    XMLSecurityDSig::SHA1 => XMLSecurityKey::SHA1_RSA_MGF1,
    XMLSecurityDSig::SHA224 => XMLSecurityKey::SHA224_RSA_MGF1,
    XMLSecurityDSig::SHA256 => XMLSecurityKey::SHA256_RSA_MGF1,
    XMLSecurityDSig::SHA384 => XMLSecurityKey::SHA384_RSA_MGF1,
    XMLSecurityDSig::SHA512 => XMLSecurityKey::SHA512_RSA_MGF1,
];

foreach ($algos as $digestAlgo => $signAlgo) {
    signAndVerify($digestAlgo, $signAlgo);
}

// verify externaly signed document
echo("Verify xml-sign-sha-rsa-mgf1.xml ...\n\n");
$doc = new DOMDocument();
$doc->load(FILE_SIGNED_DOC);
$objDSig = new XMLSecurityDSig();
$sig = $objDSig->locateSignature($doc);
$objKey = $objDSig->locateKey();
$objDSig->canonicalizeSignedInfo();
$objDSig->idKeys = array('ID');
$objDSig->validateReference();
XMLSecEnc::staticLocateKeyInfo($objKey, $sig);
$objKey->loadKey(FILE_CERT, TRUE, TRUE);
$verify = $objDSig->verify($objKey);
if ($verify !== 1) {
    echo("\tFailed to verify exernal signed doc via cert\n");
} else {
    echo("Successfully verified exernal signed doc via cert\n");
}
// verify with pubkey
$objKey->loadKey(FILE_KEY_PUB, TRUE, FALSE);
$verify = $objDSig->verify($objKey);
if ($verify !== 1) {
    echo("\tFailed to verify exernal signed doc via pubkey \n");
} else {
    echo("Successfully verified exernal signed doc via pubkey\n");
}

echo "DONE\n";
?>
--EXPECTF--
DONE
