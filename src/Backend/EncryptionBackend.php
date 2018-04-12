<?php

namespace SimpleSAML\XMLSec\Backend;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;

/**
 * Interface for backends implementing encryption.
 *
 * @package SimpleSAML\XMLSec\Backend
 */
interface EncryptionBackend
{

    /**
     * Set the cipher to be used by the backend.
     *
     * @param string $cipher The identifier of the cipher.
     *
     * @throws InvalidArgumentException If the cipher is unknown or not supported.
     *
     * @see \SimpleSAML\XMLSec\Constants
     */
    public function setCipher($cipher);


    /**
     * Encrypt a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to encrypt.
     * @param string $plaintext The original text to encrypt.
     *
     * @return string The encrypted plaintext (ciphertext).
     *
     * @throws RuntimeException If there is an error while encrypting the plaintext.
     */
    public function encrypt(AbstractKey $key, $plaintext);


    /**
     * Decrypt a given ciphertext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to decrypt.
     * @param string $ciphertext The encrypted text to decrypt.
     *
     * @return string The decrypted ciphertext (plaintext).
     *
     * @throws RuntimeException If there is an error while decrypting the ciphertext.
     */
    public function decrypt(AbstractKey $key, $ciphertext);
}
