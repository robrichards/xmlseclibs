--TEST--
A signature over an encrypted node still verifies after decryption (inclusive and exclusive C14N, inherited namespaces)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$res = openssl_pkey_new(array('private_key_bits' => 2048));
openssl_pkey_export($res, $pem);
$details = openssl_pkey_get_details($res);
$cases = array(
    'plain' => '<env><box Id="b1"><item a="1"/></box></env>',
    'inherited prefix' => '<env xmlns:p="urn:test"><box Id="b1"><p:item p:a="1"/></box></env>',
    'inherited default' => '<env xmlns="urn:d"><box Id="b1"><item/></box></env>',
    'unused prefix' => '<env xmlns:u="urn:u"><box Id="b1"><item/></box></env>',
    'attribute declared below' => '<env xmlns:p="urn:test"><box Id="b1"><p:item xsi:t="v" xmlns:xsi="urn:xsi"/></box></env>',
);
function pinned($details) {
    $pub = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $pub->loadKey($details['key']);
    return $pub;
}
foreach (array('inclusive' => XMLSecurityDSig::C14N, 'exclusive' => XMLSecurityDSig::EXC_C14N) as $cn => $c14n) {
    foreach (array('external', 'enveloped') as $place) {
        foreach (array('Element' => XMLSecEnc::Element, 'Content' => XMLSecEnc::Content) as $mn => $type) {
            $row = array();
            foreach ($cases as $label => $xml) {
                $doc = new DOMDocument();
                $doc->loadXML($xml);
                $box = $doc->documentElement->firstChild;
                $dsig = new XMLSecurityDSig();
                $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
                $dsig->addReference($box, XMLSecurityDSig::SHA256,
                    $place === 'enveloped' ? array(XMLSecurityDSig::ENVELOPED, $c14n) : array($c14n),
                    array('overwrite' => false));
                $priv = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
                $priv->loadKey($pem);
                $dsig->sign($priv);
                $dsig->appendSignature($place === 'enveloped' ? $box : $doc->documentElement);
                $doc->loadXML($doc->saveXML());           /* the signed fixture, re-parsed */
                $box = $doc->documentElement->firstChild;
                $key = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
                $key->generateSessionKey();
                $enc = new XMLSecEnc();
                $enc->setNode($box);
                $enc->type = $type;
                $encData = $enc->encryptNode($key);
                $dec = new XMLSecEnc();
                $dec->setNode($encData);
                $dec->type = $type;
                $dec->decryptNode($key);
                try {
                    $v = new XMLSecurityDSig();
                    $v->verifyDocument(pinned($details), $doc);
                    $row[] = 'ok';
                } catch (Exception $e) {
                    $row[] = 'FAIL(' . $label . ')';
                }
            }
            print "$cn $place $mn: " . implode(' ', $row) . "\n";
        }
    }
}
?>
--EXPECTF--
inclusive external Element: ok ok ok ok ok
inclusive external Content: ok ok ok ok ok
inclusive enveloped Element: ok ok ok ok ok
inclusive enveloped Content: ok ok ok ok ok
exclusive external Element: ok ok ok ok ok
exclusive external Content: ok ok ok ok ok
exclusive enveloped Element: ok ok ok ok ok
exclusive enveloped Content: ok ok ok ok ok
