<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 01:40
 */

namespace RobRichards\XMLSecLibs\Extension;


use RobRichards\XMLSecLibs\XMLSecLibsExtensionAbstract;
use RobRichards\XMLSecLibs\XMLSecLibsExtensionInterface;

class Hash_Hmac extends XMLSecLibsExtensionAbstract implements XMLSecLibsExtensionInterface
{

    /**
     * @param string $data
     * @param string $signature
     */
    public function verifySignature($data, $signature)
    {
        $expectedSignature = hash_hmac("sha1", $data, $this->key, true);
        return strcmp($signature, $expectedSignature) == 0;
    }

    /**
     * @param string $data
     * @return string
     */
    public function signData($data)
    {
        return hash_hmac("sha1", $data, $this->key, true);
    }
}