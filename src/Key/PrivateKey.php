<?php

namespace SimpleSAML\XMLSec\Key;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;

/**
 * A class modeling private keys for their use in asymmetric algorithms.
 *
 * @package SimpleSAML\XMLSec\Key
 */
class PrivateKey extends AsymmetricKey
{

    /**
     * Create a new private key from the PEM-encoded key material.
     *
     * @param string $key The PEM-encoded key material.
     * @param string $passphrase An optional passphrase used to decrypt the given key material.
     */
    public function __construct($key, $passphrase = "")
    {
        parent::__construct(openssl_pkey_get_private($key, $passphrase));
    }


    /**
     * Get a new private key from a file.
     *
     * @param string $file The file where the PEM-encoded private key is stored.
     * @param string $passphrase An optional passphrase used to decrypt the given key material.
     *
     * @return PrivateKey A new private key.
     *
     * @throws InvalidArgumentException If the file cannot be read.
     */
    public static function fromFile($file, $passphrase = "")
    {
        return new static(self::readFile($file), $passphrase);
    }
}
