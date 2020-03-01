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
    public static function compareStrings(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }
}
