--TEST--
Signatures with shaXXX-rsa-MGF1 algorithms
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('FILE_BASIC_DOC', dirname(__FILE__) . '/basic-doc.xml');
define('FILE_KEY_PRIV', dirname(__FILE__) . '/privkey.pem');
define('FILE_CERT', dirname(__FILE__) . '/mycert.pem');

function signAndVerify($digestAlgo, $signAlgo) {

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
    //$doc->save(dirname(__FILE__) . '/xml-sign-sha-rsa-mgf1.xml');

    // verify
    $objKeyPub = new XMLSecurityKey($signAlgo, array('type'=>'public'));
    $objKeyPub->loadKey(FILE_CERT, TRUE. TRUE);
    $objDSig = new XMLSecurityDSig();
    $objDSig->locateSignature($doc);
    $objDSig->canonicalizeSignedInfo();
    $objDSig->validateReference();
    $verify = $objDSig->verify($objKeyPub);
    if ($verify !== 1) {
        echo("\tFailed to verify with $signAlgo\n");
    } else {
        echo("Success with $signAlgo\n");
    }

    return;
}

$algos = [
    //XMLSecurityKey::SHA1_RSA_MGF1,
    XMLSecurityDSig::SHA256 => XMLSecurityKey::SHA256_RSA_MGF1,
    //XMLSecurityKey::SHA384_RSA_MGF1,
    //XMLSecurityKey::SHA512_RSA_MGF1,
];

foreach ($algos as $digestAlgo => $signAlgo) {
    signAndVerify($digestAlgo, $signAlgo);
}

echo "DONE\n";
?>
--EXPECTF--
DONE
