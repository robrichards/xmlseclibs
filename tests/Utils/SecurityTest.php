<?php
namespace SimpleSAML\XMLSec\Test\Utils;

use SimpleSAML\XMLSec\Utils\Security;

/**
 * A class to test SimpleSAML\XMLSec\Utils\Security.
 *
 * @package SimpleSAML\XMLSec\Test\Utils
 */
class SecurityTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Test the constant-time comparison function.
     */
    public function testCompareStrings()
    {
        // test that two equal strings compare successfully
        $this->assertTrue(Security::compareStrings('random string', 'random string'));

        // test that two different, equal-length strings fail to compare
        $this->assertFalse(Security::compareStrings('random string', 'string random'));

        // test that two different-length strings fail to compare
        $this->assertFalse(Security::compareStrings('one string', 'one string      '));
    }
}
