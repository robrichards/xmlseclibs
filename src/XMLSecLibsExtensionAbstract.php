<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 00:40
 */

namespace RobRichards\XMLSecLibs;


abstract class XMLSecLibsExtensionAbstract implements XMLSecLibsExtensionInterface
{
    /** @var string */
    protected $iv          = '';

    /** @var array  */
    protected $cryptParams = array();

    /** @var string */
    protected $key         = '';

    /**
     * @param array $params
     * @param string $key
     */
    public function __construct(array $params, $key = '') {
        $this->cryptParams = $params;
        $this->key         = $key;
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

}