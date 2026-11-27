<?php

namespace RobRichards\XMLSecLibs\Internal;

use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;

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
 * @copyright 2007-2026 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

/**
 * Key-transport algorithms an EncryptedKey may use.
 *
 * RSA-1.5, RSA-OAEP, and RSA-OAEP-MGF1P. Any other algorithm is rejected.
 * Not part of the supported extension surface.
 *
 * @internal
 */
final class KeyTransportAlgorithms
{
    private const ALGORITHMS = array(
        XMLSecurityKey::RSA_1_5,
        XMLSecurityKey::RSA_OAEP_MGF1P,
        XMLSecurityKey::RSA_OAEP,
    );

    private function __construct()
    {
    }

    /**
     * @param XMLSecurityKey $objKey
     * @return void
     * @throws Exception
     */
    public static function assertAlgorithm(XMLSecurityKey $objKey): void
    {
        $algorithm = $objKey->getAlgorithm();
        if (! is_string($algorithm) || ! in_array($algorithm, self::ALGORITHMS, true)) {
            throw new Exception(
                'EncryptedKey algorithm is not a supported key transport algorithm: \''
                . (is_string($algorithm) ? $algorithm : '') . '\''
            );
        }
    }
}
