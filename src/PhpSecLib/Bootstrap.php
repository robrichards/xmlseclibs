<?php
/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2026, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author    Robert Richards <rrichards@cdatazone.org>
 * @author    Tim Schoondergang <Tim.Schoondergang@TiMMiT.nl>
 * @copyright 2007-2026 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

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
    /**
     * Whether boot() has already bound the phpseclib classes.
     *
     * @var bool
     */
    private static $booted = false;

    /**
     * Whether the installed phpseclib is major version 4.
     *
     * @var bool
     */
    private static $version4 = false;

    /**
     * Detect the installed phpseclib major and alias its crypto classes.
     *
     * Prefers phpseclib 4 when that namespace is present, otherwise phpseclib 3.
     * A second call does nothing.
     *
     * @return void
     * @throws RuntimeException When neither phpseclib 3 nor 4 is installed.
     */
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

    /**
     * Report whether phpseclib 4 is the installed major.
     *
     * Boots the binding first when that has not happened yet.
     *
     * @return bool True when phpseclib 4 is installed.
     */
    public static function isVersion4(): bool
    {
        self::boot();
        return self::$version4;
    }

    /**
     * Alias the phpseclib 4 crypto classes into this namespace.
     *
     * @return void
     */
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

    /**
     * Alias the phpseclib 3 crypto classes into this namespace.
     *
     * @return void
     */
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

    /**
     * Publish one phpseclib class under a short name in this namespace.
     *
     * Skips the alias when that short name is already declared, so boot() can
     * run more than once in the same process.
     *
     * @param string $source Fully-qualified class name in the installed phpseclib.
     * @param string $shortName Class name to expose in this namespace.
     *
     * @return void
     */
    private static function aliasClass(string $source, string $shortName): void
    {
        $target = __NAMESPACE__ . '\\' . $shortName;
        if (class_exists($target, false)) {
            return;
        }
        class_alias($source, $target);
    }
}
