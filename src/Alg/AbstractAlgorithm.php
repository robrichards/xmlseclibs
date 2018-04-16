<?php

namespace SimpleSAML\XMLSec\Alg;

use SimpleSAML\XMLSec\Key\AbstractKey;

/**
 * An abstract class that must be extended by all cryptographic algorithms.
 *
 * @package SimpleSAML\XMLSec\Alg
 */
abstract class AbstractAlgorithm
{

    /**
     * Load a key for its use with this algorithm.
     *
     * @param AbstractKey $key The key to use.
     */
    abstract public function loadKey(AbstractKey $key);
}
