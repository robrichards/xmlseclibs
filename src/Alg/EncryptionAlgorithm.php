<?php

namespace SimpleSAML\XMLSec\Alg;

use SimpleSAML\XMLSec\Backend\EncryptionBackend;

/**
 * An interface representing algorithms that can be used for encryption.
 *
 * @package SimpleSAML\XMLSec\Alg
 */
interface EncryptionAlgorithm
{
    /**
     * Set the backend to use for actual computations by this algorithm.
     *
     * @param EncryptionBackend $backend The encryption backend to use.
     *
     * @return void
     */
    public function setBackend(EncryptionBackend $backend): void;


    /**
     * Encrypt a given plaintext with this cipher and the loaded key.
     *
     * @param string $plaintext The original text to encrypt.
     *
     * @return string The encrypted plaintext (ciphertext).
     */
    public function encrypt(string $plaintext): string;


    /**
     * Decrypt a given ciphertext with this cipher and the loaded key.
     *
     * @param string $ciphertext The encrypted text to decrypt.
     *
     * @return string The decrypted ciphertext (plaintext).
     */
    public function decrypt(string $ciphertext): string;
}
