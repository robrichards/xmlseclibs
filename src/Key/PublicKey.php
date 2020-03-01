<?php

namespace SimpleSAML\XMLSec\Key;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;

/**
 * A class modeling public keys for their use in asymmetric algorithms.
 *
 * @package SimpleSAML\XMLSec\Key
 */
class PublicKey extends AsymmetricKey
{
    /**
     * Create a new public key from the PEM-encoded key material.
     *
     * @param resource|string $key The PEM-encoded key material.
     */
    public function __construct($key)
    {
        parent::__construct(openssl_pkey_get_public($key));
    }


    /**
     * Get a new public key from a file.
     *
     * @param string $file The file where the PEM-encoded public key is stored.
     *
     * @return \SimpleSAML\XMLSec\Key\PublicKey A new public key.
     *
     * @throws \SimpleSAML\XMLSec\Exception\InvalidArgumentException If the file cannot be read.
     */
    public static function fromFile(string $file): PublicKey
    {
        return new static(static::readFile($file));
    }


    /**
     * Encode data in ASN.1.
     *
     * @param int $type The type of data.
     * @param string $string The data to encode.
     *
     * @return null|string The encoded data, or null if it was too long.
     */
    protected static function makeASN1Segment(int $type, string $string): ?string
    {
        switch ($type) {
            case 0x02:
                if (ord($string) > 0x7f) {
                    $string = chr(0) . $string;
                }
                break;
            case 0x03:
                $string = chr(0) . $string;
                break;
        }

        $length = strlen($string);

        if ($length < 128) {
            $output = sprintf("%c%c%s", $type, $length, $string);
        } elseif ($length < 0x0100) {
            $output = sprintf("%c%c%c%s", $type, 0x81, $length, $string);
        } elseif ($length < 0x010000) {
            $output = sprintf("%c%c%c%c%s", $type, 0x82, $length / 0x0100, $length % 0x0100, $string);
        } else {
            $output = null;
        }
        return $output;
    }


    /**
     * Create a new public key from its RSA details (modulus and exponent).
     *
     * @param string $modulus The modulus of the given key.
     * @param string $exponent The exponent of the given key.
     *
     * @return PublicKey A new public key with the given modulus and exponent.
     */
    public static function fromDetails(string $modulus, string $exponent): PublicKey
    {
        return new static(
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(
                base64_encode(
                    self::makeASN1Segment(
                        0x30,
                        pack("H*", "300D06092A864886F70D0101010500") . // RSA alg id
                        self::makeASN1Segment( // bitstring
                            0x03,
                            self::makeASN1Segment( // sequence
                                0x30,
                                self::makeASN1Segment(0x02, $modulus) .
                                self::makeASN1Segment(0x02, $exponent)
                            )
                        )
                    )
                ),
                64,
                "\n"
            ) .
            "-----END PUBLIC KEY-----\n"
        );
    }
}
