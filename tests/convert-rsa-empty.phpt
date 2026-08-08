--TEST--
convertRSA / makeAsnSegment reject or handle empty INTEGER input safely
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* Empty modulus must not produce a PEM (and must not warn). */
try {
    XMLSecurityKey::convertRSA('', "\x01\x00\x01");
    echo "EMPTY_MOD: unexpected success\n";
} catch (Exception $e) {
    echo "EMPTY_MOD: ".$e->getMessage()."\n";
}

/* Empty exponent must not produce a PEM. */
try {
    XMLSecurityKey::convertRSA("\x01\x02\x03", '');
    echo "EMPTY_EXP: unexpected success\n";
} catch (Exception $e) {
    echo "EMPTY_EXP: ".$e->getMessage()."\n";
}

/* Empty ASN.1 INTEGER is encoded as a single 0x00 byte (no uninitialized offset). */
$seg = XMLSecurityKey::makeAsnSegment(0x02, '');
echo "EMPTY_INT: ".(bin2hex($seg) === '020100' ? 'ok' : bin2hex($seg))."\n";

/* Non-empty high-bit INTEGER still gets a leading 0x00. */
$seg2 = XMLSecurityKey::makeAsnSegment(0x02, "\x80\x01");
echo "HIGH_BIT: ".(bin2hex($seg2) === '0203008001' ? 'ok' : bin2hex($seg2))."\n";
?>
--EXPECTF--
EMPTY_MOD: Unable to convert RSA key
EMPTY_EXP: Unable to convert RSA key
EMPTY_INT: ok
HIGH_BIT: ok
