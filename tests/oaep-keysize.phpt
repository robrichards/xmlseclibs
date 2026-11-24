--TEST--
RSA-OAEP EncryptionMethod accepts xenc:KeySize (1-999999, canonical form) and still rejects other elements
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$public = PublicKeyLoader::load(file_get_contents(__DIR__ . '/mycert.pem'));
$session = random_bytes(16);
$wrapped = base64_encode($public->withPadding(RSA::ENCRYPTION_OAEP)
    ->withHash('sha1')->withMGFHash('sha1')->encrypt($session));

function unwrap($parameters, $wrapped) {
    $doc = new DOMDocument();
    $doc->loadXML('<e:EncryptedKey xmlns:e="'.XMLSecEnc::XMLENCNS.'" xmlns:ds="'.XMLSecurityDSig::XMLDSIGNS
        .'" xmlns:e11="'.XMLSecEnc::XMLENC11NS.'"><e:EncryptionMethod Algorithm="'.XMLSecurityKey::RSA_OAEP.'">'
        .$parameters.'</e:EncryptionMethod><e:CipherData><e:CipherValue>'.$wrapped
        .'</e:CipherValue></e:CipherData></e:EncryptedKey>');
    $key = XMLSecurityKey::fromEncryptedKeyElement($doc->documentElement);
    $key->loadKey(__DIR__ . '/privkey.pem', true);
    return $key->encryptedCtx->decryptKey($key);
}

$digest = '<ds:DigestMethod Algorithm="'.XMLSecurityDSig::SHA1.'"/>';
$cases = array(
    'KeySize only' => '<e:KeySize>2048</e:KeySize>',
    'KeySize with parameters' => '<e:KeySize> 2048 </e:KeySize>'.$digest
        .'<e11:MGF Algorithm="'.XMLSecEnc::XMLENC11NS.'mgf1sha1"/>',
    'duplicate KeySize' => '<e:KeySize>2048</e:KeySize><e:KeySize>2048</e:KeySize>',
    'non-numeric KeySize' => '<e:KeySize>large</e:KeySize>',
    'zero KeySize' => '<e:KeySize>0</e:KeySize>',
    'nested KeySize' => '<e:KeySize><e:Bits>2048</e:Bits></e:KeySize>',
    'KeySize wrong namespace' => '<e11:KeySize>2048</e11:KeySize>',
    'unknown extension' => '<x:Extension xmlns:x="urn:example"/>',
    'KeySize one' => '<e:KeySize>1</e:KeySize>',
    'KeySize upper bound' => '<e:KeySize>999999</e:KeySize>',
    'KeySize above bound' => '<e:KeySize>1000000</e:KeySize>',
    'KeySize huge' => '<e:KeySize>'.str_repeat('9', 40).'</e:KeySize>',
    'KeySize plus sign' => '<e:KeySize>+2048</e:KeySize>',
    'KeySize leading zero' => '<e:KeySize>02048</e:KeySize>',
    'KeySize negative' => '<e:KeySize>-1</e:KeySize>',
    'KeySize trailing newline' => "<e:KeySize>2048\n</e:KeySize>",
);
foreach ($cases as $name => $parameters) {
    try {
        echo "$name: ".(unwrap($parameters, $wrapped) === $session ? 'OK' : 'WRONG KEY')."\n";
    } catch (Exception $e) {
        echo "$name: ".$e->getMessage()."\n";
    }
}
?>
--EXPECTF--
KeySize only: OK
KeySize with parameters: OK
duplicate KeySize: Duplicate RSA-OAEP parameter: KeySize
non-numeric KeySize: Invalid RSA-OAEP parameter content
zero KeySize: Invalid RSA-OAEP parameter content
nested KeySize: Invalid RSA-OAEP parameter content
KeySize wrong namespace: Unsupported RSA-OAEP parameter element
unknown extension: Unsupported RSA-OAEP parameter element
KeySize one: OK
KeySize upper bound: OK
KeySize above bound: Invalid RSA-OAEP parameter content
KeySize huge: Invalid RSA-OAEP parameter content
KeySize plus sign: Invalid RSA-OAEP parameter content
KeySize leading zero: Invalid RSA-OAEP parameter content
KeySize negative: Invalid RSA-OAEP parameter content
KeySize trailing newline: OK
