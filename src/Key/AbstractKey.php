<?php

namespace SimpleSAML\XMLSec\Key;

/**
 * A class representing a key.
 *
 * This class can be extended in order to implement specific types of keys.
 *
 * @package SimpleSAML\XMLSec\Key
 */
abstract class AbstractKey
{

    /** @var mixed */
    protected $key_material;


    /**
     * Build a new key with $key as its material.
     *
     * @param mixed $key The associated key material.
     */
    public function __construct($key)
    {
        $this->key_material = $key;
    }


    /**
     * Return the key material associated with this key.
     *
     * @return mixed The key material.
     */
    public function get()
    {
        return $this->key_material;
    }
}
