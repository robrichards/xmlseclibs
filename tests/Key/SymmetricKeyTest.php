<?php

namespace SimpleSAML\XMLSec\Test\Key;

use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Class to test SimpleSAML\XMLSec\Key\SymmetricKey
 *
 * @package SimpleSAML\XMLSec\Test\Key
 */
class SymmetricKeyTest extends TestCase
{

    /**
     * Cover basic creation, retrieval and length computation.
     */
    public function testCreation()
    {
        $k = new SymmetricKey('secret_key_material');
        $this->assertEquals('secret_key_material', $k->get());
        $this->assertEquals(19, $k->getLength());
    }


    /**
     * Cover random generation of secrets.
     */
    public function testGeneration()
    {
        $k1 = SymmetricKey::generate(24, true);
        $k2 = SymmetricKey::generate(24, true);
        $this->assertEquals(24, $k1->getLength());
        $this->assertEquals(24, $k2->getLength());
        $this->assertNotEquals($k1->get(), $k2->get());
    }
}
