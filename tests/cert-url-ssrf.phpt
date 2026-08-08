--TEST--
staticAdd509Cert URL fetching is SSRF-hardened
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

$doc = new DOMDocument();
$doc->loadXML('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>');
$sig = $doc->documentElement;

$cases = array(
    'FILE'        => 'file:///etc/passwd',
    'SCHEME'      => 'ftp://example.com/cert.pem',
    'LOOPBACK'    => 'http://127.0.0.1/cert.pem',
    'LINKLOCAL'   => 'http://169.254.169.254/latest/meta-data/',
    'PRIVATE'     => 'http://10.0.0.5/cert.pem',
    'IPV6LOOP'    => 'http://[::1]/cert.pem',
    'CGNAT'       => 'http://100.64.1.1/cert.pem',
    'MAPPEDLOOP'  => 'http://[::ffff:127.0.0.1]/cert.pem',
    'MAPPEDPRIV'  => 'http://[::ffff:10.0.0.1]/cert.pem',
    'MAPPEDMETA'  => 'http://[::ffff:169.254.169.254]/cert.pem',
);

foreach ($cases as $label => $url) {
    try {
        XMLSecurityDSig::staticAdd509Cert($sig, $url, true, true);
        print "$label: unexpected success\n";
    } catch (Exception $e) {
        print "$label: ".$e->getMessage()."\n";
    }
}

/* file:// can be explicitly opted into. */
$tmp = tempnam(sys_get_temp_dir(), 'cert');
file_put_contents($tmp, "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
try {
    XMLSecurityDSig::staticAdd509Cert($sig, 'file://'.$tmp, true, true, null, array('allow_file_scheme' => true));
    print "FILE_OPTIN: OK\n";
} catch (Exception $e) {
    print "FILE_OPTIN: ".$e->getMessage()."\n";
}
unlink($tmp);
?>
--EXPECTF--
FILE: file:// certificate URLs are disabled
SCHEME: Unsupported certificate URL scheme
LOOPBACK: Certificate URL host is not allowed
LINKLOCAL: Certificate URL host is not allowed
PRIVATE: Certificate URL host is not allowed
IPV6LOOP: Certificate URL host is not allowed
CGNAT: Certificate URL host is not allowed
MAPPEDLOOP: Certificate URL host is not allowed
MAPPEDPRIV: Certificate URL host is not allowed
MAPPEDMETA: Certificate URL host is not allowed
FILE_OPTIN: OK
