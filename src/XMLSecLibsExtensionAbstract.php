<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 00:40
 */

namespace RobRichards\XMLSecLibs;

use RobRichards\XMLSecLibs\XMLSecLibsExtensionInterface;

abstract class XMLSecLibsExtensionAbstract implements XMLSecLibsExtensionInterface
{
    /** @var string */
    protected $iv          = '';

    /** @var array  */
    protected $cryptParams = array();

    /** @var string */
    protected $key         = '';

    /** @var string */
    protected $passphrase  = '';

    /** @var int    */
    protected $type        = 0;

    /**
     * @param array $params
     * @param string $key
     */
    public function __construct(array $params, $key = '') {
        $this->cryptParams = $params;
        $this->key         = $key;
    }

    /**
     * @param int $type
     */
    public function setType($type)
    {
        $this->type = $type;
    }

    /**
     * @param string $passphrase
     */
    public function setPassphrase($passphrase)
    {
        $this->passphrase = $passphrase;
    }

    /**
     * @param string $data
     * @throws XMLSecLibsException
     */
    public function encrypt($data) {
        throw new XMLSecLibsException('Method not implemented yet');
    }

    /**
     * @param string $data
     * @throws XMLSecLibsException
     */
    public function decrypt($data) {
        throw new XMLSecLibsException('Method not implemented yet');
    }

    /**
     * @param string $data
     * @param string $signature
     * @throws XMLSecLibsException
     */
    public function verifySignature($data, $signature) {
        throw new XMLSecLibsException('Method not implemented yet');
    }

    /**
     * @param string $data
     * @throws XMLSecLibsException
     */
    public function signData($data) {
        throw new XMLSecLibsException('Method not implemented yet');
    }

    /**
     * @param $key
     * @param bool|false $isFile
     * @param bool|false $isCert
     */
    public function loadKey($key, $isFile = false, $isCert = false)
    {
        throw new XMLSecLibsException('Method not implemented yet');
    }

}