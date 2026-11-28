--TEST--
add509Cert limits the size of a remote certificate response body
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

/*
 * The host check rejects loopback and private addresses, so no local server
 * can be used. Instead an "http" stream wrapper stands in for the network:
 * the URL is a public IP literal (nothing is resolved or connected to) and
 * the wrapper serves a body with no Content-Length header, counting the
 * bytes the client pulls and whether the stream was closed.
 */
class FakeHttpBody
{
    public static $body = '';
    public static $infinite = false;
    public static $served = 0;
    public static $closed = 0;
    public static $opened = 0;
    public static $url = null;
    public static $options = null;
    public $context;
    private $pos = 0;

    public static function reset($body, $infinite = false)
    {
        self::$body = $body;
        self::$infinite = $infinite;
        self::$served = 0;
        self::$closed = 0;
        self::$opened = 0;
    }

    public function stream_open($path, $mode, $options, &$opened)
    {
        self::$opened++;
        self::$url = $path;
        self::$options = stream_context_get_options($this->context);
        return strpos($path, '://93.184.216.34:1/') === false;
    }

    public function stream_read($count)
    {
        if (self::$infinite) {
            self::$served += $count;
            return str_repeat('A', $count);
        }
        $chunk = (string) substr(self::$body, $this->pos, $count);
        $this->pos += strlen($chunk);
        self::$served += strlen($chunk);
        return $chunk;
    }

    public function stream_eof()
    {
        return ! self::$infinite && $this->pos >= strlen(self::$body);
    }

    public function stream_stat()
    {
        return array();
    }

    public function stream_close()
    {
        self::$closed++;
    }
}

function newSignature($withKeyInfo = false)
{
    $xml = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
    if ($withKeyInfo) {
        $xml .= '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>QUJD</ds:X509Certificate></ds:X509Data></ds:KeyInfo>';
    }
    $doc = new DOMDocument();
    $doc->loadXML($xml . '</ds:Signature>');
    return $doc;
}

function certNodes($doc)
{
    $out = array();
    foreach ($doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'X509Certificate') as $n) {
        $out[] = $n->nodeValue;
    }
    return $out;
}

$url = 'http://93.184.216.34/cert.pem';
$pem = file_get_contents(dirname(__FILE__) . '/mycert.pem');
preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $pem, $m);
$b64 = preg_replace('/\s+/', '', $m[1]);
$limit = XMLSecurityDSig::MAX_REMOTE_CERT_BYTES;
print "LIMIT: $limit\n";

/* Pad a PEM with trailing text lines to an exact size. */
function padTo($pem, $size)
{
    $pad = $size - strlen($pem);
    $out = $pem;
    while ($pad > 0) {
        $n = min(64, $pad);
        $line = str_repeat('x', $n - 1) . "\n";
        $out .= ($n === 1) ? "\n" : $line;
        $pad -= $n;
    }
    return $out;
}

stream_wrapper_unregister('http');
stream_wrapper_register('http', 'FakeHttpBody');
try {
    /* 1. A certificate within the limit is added through add509Cert(). */
    FakeHttpBody::reset($pem);
    $doc = newSignature();
    $dsig = new XMLSecurityDSig();
    $dsig->sigNode = $doc->documentElement;
    $dsig->add509Cert($url, true, true);
    print 'WITHIN: ' . (certNodes($doc) === array($b64) ? 'added' : 'MISMATCH') . ', closed=' . FakeHttpBody::$closed . "\n";

    /* Request settings are unchanged. */
    $o = FakeHttpBody::$options['http'];
    print 'URL: ' . FakeHttpBody::$url . "\n";
    print 'FOLLOW: ' . $o['follow_location'] . ' MAXREDIR: ' . $o['max_redirects'] . ' TIMEOUT: ' . $o['timeout'] . "\n";
    print 'HOSTHDR: ' . trim($o['header']) . "\n";
    print 'SSL: ' . (FakeHttpBody::$options['ssl']['verify_peer'] ? 'verify_peer' : 'NO') . "\n";

    /* 2. A body of exactly the limit passes the size check. */
    $exact = padTo($pem, $limit);
    print 'EXACT SIZE: ' . strlen($exact) . "\n";
    FakeHttpBody::reset($exact);
    $doc = newSignature();
    XMLSecurityDSig::staticAdd509Cert($doc->documentElement, $url, true, true);
    print 'EXACT: ' . (certNodes($doc) === array($b64) ? 'added' : 'MISMATCH') . ', closed=' . FakeHttpBody::$closed . "\n";

    /* 3. One byte over the limit is rejected before KeyInfo is touched. */
    $over = padTo($pem, $limit + 1);
    print 'OVER SIZE: ' . strlen($over) . "\n";
    FakeHttpBody::reset($over);
    $doc = newSignature();
    $before = $doc->saveXML();
    try {
        XMLSecurityDSig::staticAdd509Cert($doc->documentElement, $url, true, true);
        print "OVER: unexpected success\n";
    } catch (Exception $e) {
        print 'OVER: ' . $e->getMessage() . ', closed=' . FakeHttpBody::$closed . "\n";
    }
    print 'OVER NO KEYINFO: ' . ($doc->saveXML() === $before ? 'unchanged' : 'CHANGED') . "\n";

    /* 4. An existing KeyInfo is left intact after a rejected download. */
    FakeHttpBody::reset($over);
    $doc = newSignature(true);
    $before = $doc->saveXML();
    try {
        $dsig = new XMLSecurityDSig();
        $dsig->sigNode = $doc->documentElement;
        $dsig->add509Cert($url, true, true, array('issuerSerial' => true, 'subjectName' => true));
        print "KEYINFO: unexpected success\n";
    } catch (Exception $e) {
        print 'KEYINFO: ' . $e->getMessage() . "\n";
    }
    print 'KEYINFO DOC: ' . ($doc->saveXML() === $before ? 'unchanged' : 'CHANGED') . "\n";

    /* 5. An endless body without Content-Length stops near the limit. */
    FakeHttpBody::reset('', true);
    $doc = newSignature(true);
    $before = $doc->saveXML();
    try {
        XMLSecurityDSig::staticAdd509Cert($doc->documentElement, $url, true, true);
        print "ENDLESS: unexpected success\n";
    } catch (Exception $e) {
        print 'ENDLESS: ' . $e->getMessage() . "\n";
    }
    $extra = FakeHttpBody::$served - ($limit + 1);
    print 'ENDLESS READ: ' . (FakeHttpBody::$served >= $limit + 1 && $extra <= 8192 ? 'stopped within one chunk of limit+1' : 'READ ' . FakeHttpBody::$served) . ', closed=' . FakeHttpBody::$closed . "\n";
    print 'ENDLESS DOC: ' . ($doc->saveXML() === $before ? 'unchanged' : 'CHANGED') . "\n";

    /* 6. A multi-MiB finite body is not read past the limit. */
    $big = str_repeat('A', 5 * 1048576);
    FakeHttpBody::reset($big);
    try {
        XMLSecurityDSig::staticAdd509Cert(newSignature()->documentElement, $url, true, true);
        print "BIG: unexpected success\n";
    } catch (Exception $e) {
        print 'BIG: ' . $e->getMessage() . "\n";
    }
    print 'BIG READ: ' . (FakeHttpBody::$served <= $limit + 1 + 8192 ? 'stopped before the rest of the body' : 'READ ' . FakeHttpBody::$served) . ', closed=' . FakeHttpBody::$closed . "\n";

    /* 7. A download that cannot be opened still reports the existing error. */
    FakeHttpBody::reset($pem);
    set_error_handler(function () { return true; });
    try {
        XMLSecurityDSig::staticAdd509Cert(newSignature()->documentElement, 'http://93.184.216.34:1/', true, true);
        print "NOOPEN: unexpected success\n";
    } catch (Exception $e) {
        print 'NOOPEN: ' . $e->getMessage() . "\n";
    }
    restore_error_handler();
} finally {
    @stream_wrapper_unregister('http');
    stream_wrapper_restore('http');
}

/* Inline certificates are not subject to the download limit. */
$doc = newSignature();
$big = "-----BEGIN CERTIFICATE-----\n" . chunk_split(str_repeat('QUJD', 400000), 64, "\n") . "-----END CERTIFICATE-----\n";
XMLSecurityDSig::staticAdd509Cert($doc->documentElement, $big, true, false);
print 'INLINE: ' . strlen(certNodes($doc)[0]) . "\n";

/* file:// remains opt-in and unchanged. */
$tmp = tempnam(sys_get_temp_dir(), 'cert');
file_put_contents($tmp, $pem);
$doc = newSignature();
XMLSecurityDSig::staticAdd509Cert($doc->documentElement, 'file://' . $tmp, true, true, null, array('allow_file_scheme' => true));
print 'FILE_OPTIN: ' . (certNodes($doc) === array($b64) ? 'added' : 'MISMATCH') . "\n";
unlink($tmp);
?>
--EXPECTF--
LIMIT: 1048576
WITHIN: added, closed=1
URL: http://93.184.216.34:80/cert.pem
FOLLOW: 0 MAXREDIR: 0 TIMEOUT: 10
HOSTHDR: Host: 93.184.216.34
SSL: verify_peer
EXACT SIZE: 1048576
EXACT: added, closed=1
OVER SIZE: 1048577
OVER: Remote certificate exceeds the maximum size of 1048576 bytes, closed=1
OVER NO KEYINFO: unchanged
KEYINFO: Remote certificate exceeds the maximum size of 1048576 bytes
KEYINFO DOC: unchanged
ENDLESS: Remote certificate exceeds the maximum size of 1048576 bytes
ENDLESS READ: stopped within one chunk of limit+1, closed=1
ENDLESS DOC: unchanged
BIG: Remote certificate exceeds the maximum size of 1048576 bytes
BIG READ: stopped before the rest of the body, closed=1
NOOPEN: Unable to load certificate from URL
INLINE: 1600000
FILE_OPTIN: added
