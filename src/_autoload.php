<?php

/**
 * Temporary autoloader to ensure compatibility with old, non-PSR-2 compliant classes.
 *
 * @author Jaime Pérez Crespo <jaime.perez@uninett.no>
 */

/**
 * Autoload function that looks for classes migrated to PSR-2.
 *
 * @param string $className Name of the class.
 */
function xmlseclibs_autoload($className)
{
    // handle the new namespaces
    $newClasses = array(
        'XMLSecEnc' => '\\RobRichards\\XMLSecLibs\\XMLSecEnc',
        'XMLSecurityDSig' => '\\RobRichards\\XMLSecLibs\\XMLSecurityDSig',
        'XMLSecurityKey' => '\\RobRichards\\XMLSecLibs\\XMLSecurityKey',

    );

    $file = dirname(__FILE__).'/'.$className.'.php';
    if (file_exists($file)) {
        require_once($file);
        class_alias($newClasses[$className], $className);
        // maybe log a warning here?
    }

}

spl_autoload_register('xmlseclibs_autoload');
