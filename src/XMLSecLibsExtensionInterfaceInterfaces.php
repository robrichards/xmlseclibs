<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 00:26
 */

namespace RobRichards\XMLSecLibs;


interface XMLSecLibsExtensionInterface
{

    /**
     * @param $data
     * @return mixed
     */
    public function encrypt($data);

    /**
     * @param $data
     * @return mixed
     */
    public function decrypt($data);

    /**
     * @param $data
     * @param $signature
     * @return mixed
     */
    public function verifySignature($data, $signature);

    /**
     * @param string $data
     * @return mixed
     */
    public function signData($data);

}