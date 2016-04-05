<?php

namespace RobRichards\XMLSecLibs\Tests;

/**
 *
 * Test case base class
 * @author Jelle Vink <jelle.vink@gmail.com>
 *
 */
class TestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * Get fixture filename
     * @param string $file File name
     * @param boolean $legacy Use legacy file location
     * @return string
     */
    protected function getFixtureFileName($file, $legacy = false)
    {
        return $legacy ? __DIR__ . '/../' . $file :  __DIR__ . '/Fixture/' . $file;
    }
}
