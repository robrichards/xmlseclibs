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
 * @copyright 2007-2026 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version   4.1.0
 */

// Load the Composer autoloader that provides phpseclib. Use the package's own
// vendor/ directory (a git clone) or, when installed as a dependency
// (<vendor-dir>/robrichards/xmlseclibs), the dependent project's autoloader.
// Skip this when the dependencies are already available, for example when the
// application has already loaded vendor/autoload.php.
if (!class_exists('phpseclib3\\Crypt\\RSA')) {
    $xmlseclibs_autoload = null;
    foreach ([__DIR__ . '/vendor/autoload.php', dirname(__DIR__, 2) . '/autoload.php'] as $xmlseclibs_candidate) {
        if (is_file($xmlseclibs_candidate)) {
            $xmlseclibs_autoload = $xmlseclibs_candidate;
            break;
        }
    }
    if ($xmlseclibs_autoload === null) {
        throw new RuntimeException(
            'xmlseclibs: Composer autoloader not found. Run "composer install" or load vendor/autoload.php before including xmlseclibs.php.'
        );
    }
    require_once $xmlseclibs_autoload;
    unset($xmlseclibs_autoload, $xmlseclibs_candidate);
}
$xmlseclibs_srcdir = dirname(__FILE__) . '/src/';
require_once $xmlseclibs_srcdir . '/XMLSecurityKey.php';
require_once $xmlseclibs_srcdir . '/XMLSecurityDSig.php';
require_once $xmlseclibs_srcdir . '/XMLSecEnc.php';
require_once $xmlseclibs_srcdir . '/Utils/XPath.php';
