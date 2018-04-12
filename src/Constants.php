<?php

namespace SimpleSAML\XMLSec;

/**
 * A collection of constants used in this library, as defined by the XMLSec set of recommendations.
 *
 * @package SimpleSAML\XMLSec
 */
class Constants
{

    /**
     * Digest algorithms
     */
    const DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const DIGEST_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const DIGEST_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    const DIGEST_SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    const DIGEST_RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    public static $DIGEST_ALGORITHMS = [
        self::DIGEST_SHA1 => 'sha1',
        self::DIGEST_SHA224 => 'sha224',
        self::DIGEST_SHA256 => 'sha256',
        self::DIGEST_SHA384 => 'sha384',
        self::DIGEST_SHA512 => 'sha512',
        self::DIGEST_RIPEMD160 => 'ripemd160',
    ];

    /**
     * Padding schemas
     */
    const PADDING_PKCS1 = 1;
    const PADDING_PKCS1_OAEP = 4;

    /**
     * Block encryption algorithms
     */
    const BLOCK_ENC_3DES = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    const BLOCK_ENC_AES128 = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    const BLOCK_ENC_AES192 = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    const BLOCK_ENC_AES256 = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    const BLOCK_ENC_AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
    const BLOCK_ENC_AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
    const BLOCK_ENC_AES256_GCM = 'http://www.w3.org/2009xmlenc11#aes256-gcm';

    public static $BLOCK_CIPHER_ALGORITHMS = [
        self::BLOCK_ENC_3DES => 'des-ede3-cbc',
        self::BLOCK_ENC_AES128 => 'aes-128-cbc',
        self::BLOCK_ENC_AES192 => 'aes-192-cbc',
        self::BLOCK_ENC_AES256 => 'aes-256-cb',
        self::BLOCK_ENC_AES128_GCM => 'aes-128-gcm',
        self::BLOCK_ENC_AES192_GCM => 'aes-192-gcm',
        self::BLOCK_ENC_AES256_GCM => 'aes-256-gcm',
    ];

    public static $BLOCK_SIZES = [
        self::BLOCK_ENC_3DES => 8,
        self::BLOCK_ENC_AES128 => 16,
        self::BLOCK_ENC_AES192 => 16,
        self::BLOCK_ENC_AES256 => 16,
        self::BLOCK_ENC_AES128_GCM => 16,
        self::BLOCK_ENC_AES192_GCM => 16,
        self::BLOCK_ENC_AES256_GCM => 16,
    ];

    public static $BLOCK_CIPHER_KEY_SIZES = [
        self::BLOCK_ENC_3DES => 24,
        self::BLOCK_ENC_AES128 => 16,
        self::BLOCK_ENC_AES192 => 24,
        self::BLOCK_ENC_AES256 => 32,
        self::BLOCK_ENC_AES128_GCM => 16,
        self::BLOCK_ENC_AES192_GCM => 24,
        self::BLOCK_ENC_AES256_GCM => 32,
    ];

    /**
     * Canonicalization algorithms
     */
    const C14N_INCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const C14N_INCLUSIVE_WITHOUT_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_EXCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    const C14N_EXCLUSIVE_WITHOUT_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /**
     * Signature algorithms
     */
    const SIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const SIG_RSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
    const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const SIG_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    const SIG_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    const SIG_RSA_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
    const SIG_HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    const SIG_HMAC_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224";
    const SIG_HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
    const SIG_HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
    const SIG_HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
    const SIG_HMAC_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

    /**
     * XML & XPath namespaces and identifiers
     */
    const XMLDSIGNS = "http://www.w3.org/2000/09/xmldsig#";
    const XMLDSIG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    const XPATH_URI = 'http://www.w3.org/TR/1999/REC-xpath-19991116';
}
