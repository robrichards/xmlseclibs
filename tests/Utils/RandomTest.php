<?php

namespace SimpleSAML\XMLSec\Test\Utils;

use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Utils\Random;

/**
 * Tests for SimpleSAML\XMLSec\Utils\Random
 *
 * @package SimpleSAML\XMLSec\Test\Utils
 */
class RandomTest extends TestCase
{

    /**
     * Test generation of random GUIDs.
     */
    public function testGenerateGUID()
    {
        $mainRegEx = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';

        // test with default prefix
        $this->assertRegExp('/_'.$mainRegEx.'/', Random::generateGUID());

        // test with different prefix
        $this->assertRegExp('/pfx'.$mainRegEx.'/', Random::generateGUID('pfx'));
    }
}
