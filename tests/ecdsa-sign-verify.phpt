--TEST--
ECDSA sign and verify on P-256, P-384 and P-521, including cross curve/digest pairs
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* curve => array of signature algorithms. The r || s width depends only on
 * the curve, so ecdsa-sha512 on P-256 and ecdsa-sha256 on P-521 are tested. */
$arTests = array(
    'p256' => array(XMLSecurityKey::ECDSA_SHA256, XMLSecurityKey::ECDSA_SHA512),
    'p384' => array(XMLSecurityKey::ECDSA_SHA384),
    'p521' => array(XMLSecurityKey::ECDSA_SHA512, XMLSecurityKey::ECDSA_SHA256),
);

foreach ($arTests AS $curve => $algorithms) {
    foreach ($algorithms AS $algorithm) {
        $doc = new DOMDocument();
        $doc->load(dirname(__FILE__) . '/basic-doc.xml');

        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objDSig->addReference($doc, XMLSecurityDSig::SHA256, array(XMLSecurityDSig::ENVELOPED));

        $objKey = new XMLSecurityKey($algorithm, array('type' => 'private'));
        $objKey->loadKey(dirname(__FILE__) . "/ec-$curve-key.pem", true);
        $objDSig->sign($objKey);
        $objDSig->add509Cert(file_get_contents(dirname(__FILE__) . "/ec-$curve-cert.pem"));
        $objDSig->appendSignature($doc->documentElement);

        $signed = $doc->saveXML();
        $alg = substr($algorithm, strpos($algorithm, '#') + 1);

        /* Verify a freshly parsed copy with a pinned certificate and the
         * default verifyDocument() allowlist. */
        $doc = new DOMDocument();
        $doc->loadXML($signed);
        $objXMLSecDSig = new XMLSecurityDSig();
        $objPub = new XMLSecurityKey($algorithm, array('type' => 'public'));
        $objPub->loadKey(dirname(__FILE__) . "/ec-$curve-cert.pem", true, true);
        try {
            $nodes = $objXMLSecDSig->verifyDocument($objPub, $doc);
            $result = count($nodes) > 0 ? 'valid' : 'invalid';
        } catch (Exception $e) {
            $result = $e->getMessage();
        }
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $sigLength = strlen(base64_decode($xpath->evaluate('string(//ds:SignatureValue)')));
        print "$curve $alg: $result, r||s $sigLength bytes\n";

        /* Tampered content must not verify. */
        $doc = new DOMDocument();
        $doc->loadXML(str_replace('Hello, World!', 'Hello, World?', $signed));
        $objXMLSecDSig = new XMLSecurityDSig();
        try {
            $objXMLSecDSig->verifyDocument($objPub, $doc);
            print "$curve $alg tampered: unexpected success\n";
        } catch (Exception $e) {
            print "$curve $alg tampered: rejected\n";
        }
    }
}
?>
--EXPECTF--
p256 ecdsa-sha256: valid, r||s 64 bytes
p256 ecdsa-sha256 tampered: rejected
p256 ecdsa-sha512: valid, r||s 64 bytes
p256 ecdsa-sha512 tampered: rejected
p384 ecdsa-sha384: valid, r||s 96 bytes
p384 ecdsa-sha384 tampered: rejected
p521 ecdsa-sha512: valid, r||s 132 bytes
p521 ecdsa-sha512 tampered: rejected
p521 ecdsa-sha256: valid, r||s 132 bytes
p521 ecdsa-sha256 tampered: rejected
