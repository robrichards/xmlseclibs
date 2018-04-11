<?php

namespace SimpleSAML\XMLSec\Utils;

/**
 * A collection of security-related functions.
 *
 * @package SimpleSAML\XMLSec\Utils
 */
class Security
{

    /**
     * Compare two strings in constant time.
     *
     * This function allows us to compare two given strings without any timing side channels
     * leaking information about them.
     *
     * @param string $known The reference string.
     * @param string $user The user-provided string to test.
     *
     * @return bool True if both strings are equal, false otherwise.
     */
    public static function compareStrings($known, $user)
    {
        if (function_exists('hash_equals')) {
            // use hash_equals() if available (PHP >= 5.6)
            return hash_equals($known, $user);
        }

        // compare manually in constant time
        $len = mb_strlen($known, '8bit');
        if ($len !== mb_strlen($user, '8bit')) {
            return false; // length differs
        }

        $diff = 0;
        for ($i = 0; $i < $len; $i++) {
            $diff |= ord($known[$i]) ^ ord($user[$i]);
        }

        // if all the bytes in $known and $user are identical, $diff should be equal to 0
        return $diff === 0;
    }
}
