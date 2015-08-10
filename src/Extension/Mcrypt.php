<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 00:48
 */

namespace RobRichards\XMLSecLibs\Extension;


use RobRichards\XMLSecLibs\XMLSecLibsExtensionAbstract;
use RobRichards\XMLSecLibs\XMLSecLibsExtensionInterface;
use RobRichards\XMLSecLibs\XMLSecLibsException;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Mcrypt extends XMLSecLibsExtensionAbstract implements XMLSecLibsExtensionInterface
{

    /**
     * @param string $data plain data
     *
     * @return string encrypted data
     */
    public function encrypt($data)
    {
        $td = mcrypt_module_open($this->cryptParams['cipher'], '', $this->cryptParams['mode'], '');
        $this->iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $this->key, $this->iv);
        if ($this->cryptParams['mode'] == MCRYPT_MODE_CBC) {
            $bs = mcrypt_enc_get_block_size($td);
            for ($datalen0 = $datalen = strlen($data); (($datalen % $bs) != ($bs - 1)); $datalen++)
                $data .= chr(mt_rand(1, 127));
            $data .= chr($datalen - $datalen0 + 1);
        }
        $encrypted_data = $this->iv.mcrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $encrypted_data;
    }

    /**
     * @param string $data encrypted data
     *
     * @return string decrypted data
     */
    public function decrypt($data)
    {
        $td = mcrypt_module_open($this->cryptParams['cipher'], '', $this->cryptParams['mode'], '');
        $iv_length = mcrypt_enc_get_iv_size($td);

        $this->iv = substr($data, 0, $iv_length);
        $data = substr($data, $iv_length);

        mcrypt_generic_init($td, $this->key, $this->iv);
        $decrypted_data = mdecrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        if ($this->cryptParams['mode'] == MCRYPT_MODE_CBC) {
            $dataLen = strlen($decrypted_data);
            $paddingLength = substr($decrypted_data, $dataLen - 1, 1);
            $decrypted_data = substr($decrypted_data, 0, $dataLen - ord($paddingLength));
        }
        return $decrypted_data;
    }

    public function loadKey($key, $isFile = false, $isCert = false)
    {
        if ($isFile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }
        $this->x509Certificate = null;

        if ($this->cryptParams['cipher'] == MCRYPT_RIJNDAEL_128) {
            /* Check key length */
            switch ($this->type) {
                case (XMLSecurityKey::AES256_CBC):
                    if (strlen($this->key) < 25) {
                        throw new XMLSecLibsException('Key must contain at least 25 characters for this cipher');
                    }
                    break;
                case (XMLSecurityKey::AES192_CBC):
                    if (strlen($this->key) < 17) {
                        throw new XMLSecLibsException('Key must contain at least 17 characters for this cipher');
                    }
                    break;
            }
        }
    }

}