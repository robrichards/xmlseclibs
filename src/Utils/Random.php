<?php

namespace SimpleSAML\XMLSec\Utils;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;

/**
 * A collection of utilities to generate cryptographically-secure random data.
 *
 * @package SimpleSAML\XMLSec\Utils
 */
class Random
{
    /**
     * Generate a given amount of cryptographically secure random bytes.
     *
     * @param int $length The amount of bytes required.
     *
     * @return string A random string of $length length.
     *
     * @throws \SimpleSAML\XMLSec\Exception\InvalidArgumentException If $length is not an integer greater than zero.
     * @throws \SimpleSAML\XMLSec\Exception\RuntimeException If no appropriate sources of cryptographically
     *   secure random generators are available.
     */
    public static function generateRandomBytes(int $length): string
    {
        if ($length < 1) {
            throw new InvalidArgumentException('Invalid length received to generate random bytes.');
        }

        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new RuntimeException(
                'Cannot generate random bytes, no cryptographically secure random ' . 'generator available.'
            );
        }
    }


    /**
     * Generate a globally unique identifier.
     *
     * @param string $prefix Prefix to be prepended to the identifier.
     *
     * @return string A random globally unique identifier.
     */
    public static function generateGUID(string $prefix = '_'): string
    {
        $uuid = bin2hex(self::generateRandomBytes(16));
        return $prefix . substr($uuid, 0, 8) . '-' . substr($uuid, 8, 4) . '-' . substr($uuid, 12, 4) . '-'
            . substr($uuid, 16, 4) . '-' . substr($uuid, 20, 12);
    }
}
