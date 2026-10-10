<?php

namespace RobRichards\XMLSecLibs\PhpSecLib;

use RuntimeException;

/**
 * Binds this library to whichever phpseclib major is installed.
 *
 * phpseclib 3 and 4 share the crypto calls xmlseclibs uses, but live in
 * different namespaces. Alias those classes here so the rest of the library
 * can type-hint one set of names. X.509 loading differs enough that X509 is a
 * real wrapper instead of an alias.
 */
final class Bootstrap
{
    /** @var bool */
    private static $booted = false;

    /** @var bool */
    private static $version4 = false;

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        if (class_exists('phpseclib4\\Crypt\\AES')) {
            self::$version4 = true;
            self::aliasVersion4();
            return;
        }
        if (class_exists('phpseclib3\\Crypt\\AES')) {
            self::aliasVersion3();
            return;
        }
        throw new RuntimeException('robrichards/xmlseclibs requires phpseclib/phpseclib ^3.0 or ^4.0');
    }

    public static function isVersion4(): bool
    {
        self::boot();
        return self::$version4;
    }

    private static function aliasVersion4(): void
    {
        self::aliasClass('phpseclib4\\Crypt\\AES', 'AES');
        self::aliasClass('phpseclib4\\Crypt\\Common\\AsymmetricKey', 'AsymmetricKey');
        self::aliasClass('phpseclib4\\Crypt\\PublicKeyLoader', 'PublicKeyLoader');
        self::aliasClass('phpseclib4\\Crypt\\RSA', 'RSA');
        self::aliasClass('phpseclib4\\Crypt\\RSA\\PrivateKey', 'RSAPrivateKey');
        self::aliasClass('phpseclib4\\Crypt\\RSA\\PublicKey', 'RSAPublicKey');
        self::aliasClass('phpseclib4\\Crypt\\TripleDES', 'TripleDES');
    }

    private static function aliasVersion3(): void
    {
        self::aliasClass('phpseclib3\\Crypt\\AES', 'AES');
        self::aliasClass('phpseclib3\\Crypt\\Common\\AsymmetricKey', 'AsymmetricKey');
        self::aliasClass('phpseclib3\\Crypt\\PublicKeyLoader', 'PublicKeyLoader');
        self::aliasClass('phpseclib3\\Crypt\\RSA', 'RSA');
        self::aliasClass('phpseclib3\\Crypt\\RSA\\PrivateKey', 'RSAPrivateKey');
        self::aliasClass('phpseclib3\\Crypt\\RSA\\PublicKey', 'RSAPublicKey');
        self::aliasClass('phpseclib3\\Crypt\\TripleDES', 'TripleDES');
    }

    private static function aliasClass(string $source, string $shortName): void
    {
        $target = __NAMESPACE__ . '\\' . $shortName;
        if (class_exists($target, false)) {
            return;
        }
        class_alias($source, $target);
    }
}
