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

/**
 * X.509 facade with the phpseclib 3 method names.
 *
 * phpseclib 4 removed loadX509(), saveX509() and made getDN() throw unless the
 * certificate is self-signed. Callers in this library keep using the version 3
 * shape; this class picks the installed implementation.
 */
class X509
{
    /**
     * OpenSSL-compatible distinguished-name format.
     *
     * The integer matches X509::DN_OPENSSL in phpseclib 3 and 4.
     */
    const DN_OPENSSL = 3;

    /**
     * Loaded phpseclib X509 instance.
     *
     * Null until loadX509() succeeds. The concrete class is
     * phpseclib3\File\X509 or phpseclib4\File\X509.
     *
     * @var object|null
     */
    private $inner = null;

    /**
     * Load a PEM or DER X.509 certificate.
     *
     * @param string $cert Certificate contents, PEM or DER.
     *
     * @return array|false Decoded certificate, or false when parsing fails.
     */
    public function loadX509($cert)
    {
        if (Bootstrap::isVersion4()) {
            return $this->loadVersion4($cert);
        }
        return $this->loadVersion3($cert);
    }

    /**
     * Export the loaded certificate as PEM.
     *
     * phpseclib 3 re-encodes $certData. phpseclib 4 exports the object loaded
     * by loadX509() and ignores $certData.
     *
     * @param mixed $certData Decoded certificate previously returned by loadX509().
     *
     * @return string|false PEM text, or false when no certificate is loaded or export fails.
     */
    public function saveX509($certData)
    {
        if ($this->inner === null) {
            return false;
        }
        if (Bootstrap::isVersion4()) {
            return $this->saveVersion4();
        }
        return $this->inner->saveX509($certData);
    }

    /**
     * Read the subject distinguished name.
     *
     * On phpseclib 4 this calls getSubjectDN(). getDN() rejects certificates
     * that are not self-signed.
     *
     * @param int $format phpseclib DN format. Defaults to DN_OPENSSL.
     *
     * @return array|string|false Formatted subject name, or false when no certificate is loaded.
     */
    public function getDN($format = self::DN_OPENSSL)
    {
        if ($this->inner === null) {
            return false;
        }
        if (Bootstrap::isVersion4()) {
            return $this->inner->getSubjectDN($format);
        }
        return $this->inner->getDN($format);
    }

    /**
     * Read the issuer distinguished name.
     *
     * @param int $format phpseclib DN format. Defaults to DN_OPENSSL.
     *
     * @return array|string|false Formatted issuer name, or false when no certificate is loaded.
     */
    public function getIssuerDN($format = self::DN_OPENSSL)
    {
        if ($this->inner === null) {
            return false;
        }
        return $this->inner->getIssuerDN($format);
    }

    /**
     * Load a certificate with phpseclib 4.
     *
     * @param string $cert Certificate contents, PEM or DER.
     *
     * @return array|false Decoded certificate, or false when parsing fails.
     */
    private function loadVersion4($cert)
    {
        try {
            $loaded = \phpseclib4\File\X509::load($cert);
            $decoded = $loaded->toArray();
        } catch (\Throwable $e) {
            $this->inner = null;
            return false;
        }
        if (!is_array($decoded)) {
            $this->inner = null;
            return false;
        }
        $this->inner = $loaded;
        return $decoded;
    }

    /**
     * Load a certificate with phpseclib 3.
     *
     * @param string $cert Certificate contents, PEM or DER.
     *
     * @return array|false Decoded certificate, or false when parsing fails.
     */
    private function loadVersion3($cert)
    {
        $x509 = new \phpseclib3\File\X509();
        $this->inner = $x509;
        return $x509->loadX509($cert);
    }

    /**
     * Export the phpseclib 4 certificate as PEM.
     *
     * @return string|false PEM text, or false when export fails.
     */
    private function saveVersion4()
    {
        try {
            return $this->inner->toString();
        } catch (\Throwable $e) {
            return false;
        }
    }
}
