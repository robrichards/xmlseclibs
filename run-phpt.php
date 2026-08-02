<?php
/**
 * Minimal .phpt runner for local test execution without phpunit.
 * Temp scripts are written next to the .phpt so dirname(__FILE__) paths work.
 */
function parsePhpt($raw)
{
    $raw = str_replace("\r\n", "\n", $raw);
    $sections = preg_split('/^--([A-Z0-9_]+)--\s*$/m', $raw, -1, PREG_SPLIT_DELIM_CAPTURE);
    $map = array();
    for ($i = 1; $i < count($sections); $i += 2) {
        $map[$sections[$i]] = trim($sections[$i + 1], "\n");
    }
    return $map;
}

function runPhpt($file)
{
    $map = parsePhpt(file_get_contents($file));
    if (empty($map['FILE']) || (!isset($map['EXPECT']) && !isset($map['EXPECTF']))) {
        return array(false, 'parse error');
    }
    $code = $map['FILE'];
    $expect = isset($map['EXPECTF']) ? $map['EXPECTF'] : $map['EXPECT'];
    $expect = str_replace("\r\n", "\n", $expect);
    $expect = rtrim($expect);

    $dir = dirname($file);
    $tmp = $dir.'/.phpt-run-'.getmypid().'-'.mt_rand().'.php';
    file_put_contents($tmp, $code);
    $cmd = 'cd '.escapeshellarg($dir).' && '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(basename($tmp)).' 2>&1';
    $out = shell_exec($cmd);
    @unlink($tmp);
    if (!empty($map['CLEAN'])) {
        $clean = $dir.'/.phpt-clean-'.getmypid().'-'.mt_rand().'.php';
        file_put_contents($clean, $map['CLEAN']);
        shell_exec('cd '.escapeshellarg($dir).' && '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(basename($clean)).' 2>/dev/null');
        @unlink($clean);
    }
    $out = str_replace("\r\n", "\n", (string) $out);
    $out = rtrim($out);

    if (isset($map['EXPECT'])) {
        if ($out === $expect) {
            return array(true, $out);
        }
        return array(false, "EXPECTED:\n$expect\nGOT:\n$out");
    }

    $pattern = preg_quote($expect, '/');
    $pattern = str_replace(
        array('%s', '%a', '%d', '%i', '%f', '%c', '%w', '%e', '%x'),
        array('.*', '.*', '\\d+', '\\d+', '.*', '.', '\\s*', '.*', '[0-9a-fA-F]+'),
        $pattern
    );
    $pattern = '/^'.$pattern.'$/s';
    if (preg_match($pattern, $out)) {
        return array(true, $out);
    }
    return array(false, "EXPECTED:\n$expect\nGOT:\n$out");
}

$dir = isset($argv[1]) ? $argv[1] : __DIR__.'/tests';
$files = glob(rtrim($dir, '/').'/*.phpt');
sort($files);
$fail = 0;
foreach ($files as $file) {
    list($ok, $detail) = runPhpt($file);
    $name = basename($file);
    if ($ok) {
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n$detail\n";
        $fail++;
    }
}
echo ($fail === 0 ? "OK" : "FAILED")." ($fail failures)\n";
exit($fail === 0 ? 0 : 1);
