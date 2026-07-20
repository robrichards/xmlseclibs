<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

if (file_exists(dirname(__FILE__) . '/sign-basic-test.xml')) {
    unlink(dirname(__FILE__) . '/sign-basic-test.xml');
}

$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');

$objDSig = new XMLSecurityDSig();

$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$transforms = array();
for ($x = 0; $x <= 0; $x++) {
   $transform = array();
   $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query'] = '//dumynode';
    if ($x == 0) {
        $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'] = array();
        for ($y = ord('a'); $y <= ord('z'); $y++) {
            $ns_char = chr($y);
            $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'][$ns_char] = "http://$ns_char";
        }
    }
   $transforms[] = $transform;
}
$transforms[] = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
$objDSig->addReference($doc, XMLSecurityDSig::SHA1, $transforms);

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
/* load private key */
$objKey->loadKey(dirname(__FILE__) . '/privkey.pem', TRUE);

/* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


$objDSig->sign($objKey);

/* Add associated public key */
$objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/mycert.pem'));

$objDSig->appendSignature($doc->documentElement);
$doc->save(dirname(__FILE__) . '/sign-transforms-security.xml');

$sign_output = file_get_contents(dirname(__FILE__) . '/sign-basic-test.xml');
$sign_output_def = file_get_contents(dirname(__FILE__) . '/sign-basic-test.res');
if ($sign_output != $sign_output_def) {
	echo "NOT THE SAME\n";
}
echo "DONE\n";
?>

