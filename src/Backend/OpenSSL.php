<?php

namespace SimpleSAML\XMLSec\Backend;

use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;
use SimpleSAML\XMLSec\Key\AsymmetricKey;
use SimpleSAML\XMLSec\Key\PrivateKey;

/**
 * Backend for encryption and digital signatures based on the native openssl library.
 *
 * @package SimpleSAML\XMLSec\Backend
 */
class OpenSSL implements EncryptionBackend, SignatureBackend
{
    // digital signature options
    /** @var string */
    protected $digest;

    // asymmetric encryption options
    /** @var int */
    protected $padding = Constants::PADDING_PKCS1;

    // symmetric encryption options
    /** @var string */
    protected $cipher;

    /** @var int */
    protected $blocksize;

    /** @var int */
    protected $keysize;


    /**
     * Build a new OpenSSL backend.
     */
    public function __construct()
    {
        $this->setDigestAlg(Constants::DIGEST_SHA256);
        $this->setCipher(Constants::BLOCK_ENC_AES128_GCM);
    }


    /**
     * Encrypt a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to encrypt.
     * @param string $plaintext The original text to encrypt.
     *
     * @return string The encrypted plaintext (ciphertext).
     * @throws RuntimeException If there is an error while encrypting the plaintext.
     */
    public function encrypt(AbstractKey $key, $plaintext)
    {
        if ($key instanceof AsymmetricKey) {
            // asymmetric encryption
            $fn = 'openssl_public_encrypt';
            if ($key instanceof PrivateKey) {
                $fn = 'openssl_private_encrypt';
            }

            $ciphertext = null;
            if (!$fn($plaintext, $ciphertext, $key->get(), $this->padding)) {
                throw new RuntimeException('Cannot encrypt data: '.openssl_error_string());
            }
            return $ciphertext;
        }

        // symmetric encryption
        $ivlen = openssl_cipher_iv_length($this->cipher);
        if (function_exists('random_bytes')) {
            $iv = random_bytes($ivlen);
        } else {
            $iv = openssl_random_pseudo_bytes($ivlen);
        }
        $plaintext = $this->pad($plaintext);
        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->cipher,
            $key->get(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        if (!$ciphertext) {
            throw new RuntimeException('Cannot encrypt data: '.openssl_error_string());
        }
        return $iv.$ciphertext;
    }


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
    public function decrypt(AbstractKey $key, $ciphertext)
    {
        if ($key instanceof AsymmetricKey) {
            // asymmetric encryption
            $fn = 'openssl_public_decrypt';
            if ($key instanceof PrivateKey) {
                $fn = 'openssl_private_decrypt';
            }

            $plaintext = null;
            if (!$fn($ciphertext, $plaintext, $key->get(), $this->padding)) {
                throw new RuntimeException('Cannot decrypt data: '.openssl_error_string());
            }
            return $plaintext;
        }

        // symmetric encryption
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $iv = substr($ciphertext, 0, $ivlen);
        $ciphertext = substr($ciphertext, $ivlen);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->cipher,
            $key->get(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        if ($plaintext === false) {
            throw new RuntimeException('Cannot decrypt data: '.openssl_error_string());
        }
        return $this->unpad($plaintext);
    }


    /**
     * Sign a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to sign.
     * @param string $plaintext The original text to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     *
     * @throws RuntimeException If there is an error while signing the plaintext.
     */
    public function sign(AbstractKey $key, $plaintext)
    {
        if (!openssl_sign($plaintext, $signature, $key->get(), $this->digest)) {
            throw new RuntimeException('Cannot sign data: '.openssl_error_string());
        }
        return $signature;
    }


    /**
     * Verify a signature with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to verify.
     * @param string $plaintext The original signed text.
     * @param string $signature The (binary) signature to verify.
     *
     * @return boolean True if the signature can be verified, false otherwise.
     */
    public function verify(AbstractKey $key, $plaintext, $signature)
    {
        return openssl_verify($plaintext, $signature, $key->get(), $this->digest) === 1;
    }


    /**
     * Set the cipher to be used by the backend.
     *
     * @param string $cipher The identifier of the cipher.
     *
     * @throws InvalidArgumentException If the cipher is unknown or not supported.
     */
    public function setCipher($cipher)
    {
        if (!isset(Constants::$BLOCK_CIPHER_ALGORITHMS[$cipher])) {
            throw new InvalidArgumentException('Invalid or unknown cipher');
        }
        $this->cipher = Constants::$BLOCK_CIPHER_ALGORITHMS[$cipher];
        $this->blocksize = Constants::$BLOCK_SIZES[$cipher];
        $this->keysize = Constants::$BLOCK_CIPHER_KEY_SIZES[$cipher];
    }


    /**
     * Set the digest algorithm to be used by this backend.
     *
     * @param string $digest The identifier of the digest algorithm.
     *
     * @throws InvalidArgumentException If the given digest is not valid.
     */
    public function setDigestAlg($digest)
    {
        if (!isset(Constants::$DIGEST_ALGORITHMS[$digest])) {
            throw new InvalidArgumentException('Unknown digest or non-cryptographic hash function.');
        }
        $this->digest = Constants::$DIGEST_ALGORITHMS[$digest];
    }


    /**
     * Pad a plaintext using ISO 10126 padding.
     *
     * @param string $plaintext The plaintext to pad.
     *
     * @return string The padded plaintext.
     */
    public function pad($plaintext)
    {
        $padchr = $this->blocksize - (mb_strlen($plaintext) % $this->blocksize);
        $pattern = chr($padchr);
        return $plaintext.str_repeat($pattern, $padchr);
    }


    /**
     * Remove an existing ISO 10126 padding from a given plaintext.
     *
     * @param string $plaintext The padded plaintext.
     *
     * @return string The plaintext without the padding.
     */
    public function unpad($plaintext)
    {
        return substr($plaintext, 0, -ord(substr($plaintext, -1)));
    }
}
