<?php

namespace SimpleSAML\Test\Backend;

use SimpleSAML\XMLSec\Backend\OpenSSL;
use PHPUnit\Framework\Error\Error;
use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\PrivateKey;
use SimpleSAML\XMLSec\Key\PublicKey;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Tests for SimpleSAML\XMLSec\Backend\OpenSSL.
 *
 * @package SimpleSAML\Test\Backend
 */
class OpenSSLTest extends TestCase
{

    /** @var PrivateKey */
    protected $privKey;

    /** @var PublicKey */
    protected $pubKey;

    /** @var OpenSSL */
    protected $backend;

    /** @var string */
    protected $validSig;

    /** @var SymmetricKey */
    protected $sharedKey;

    protected function setUp(): void
    {
        $this->privKey = PrivateKey::fromFile('tests/privkey.pem');
        $this->pubKey = PublicKey::fromFile('tests/pubkey.pem');
        $this->sharedKey = new SymmetricKey(hex2bin('54c98b0ea7d98186c27a6c0c6f35ee1a'));
        $this->backend = new OpenSSL();
        $this->backend->setDigestAlg(Constants::DIGEST_SHA256);
        $this->backend->setCipher(Constants::BLOCK_ENC_AES256_GCM);
        $this->validSig =
            'cdd80e925e509f954807448217157367c00f7ff53c5eec74ea51ef5fee48a048283b37639c7f43400631fa2b9063a1ed05710'.
            '4721887a10ad62f128c26e01f363538a84ad261f40b80df86de9cc920d1dce2c27058da81d9c7aa0e68e459ab94995e27e57d'.
            '183ff08188b338f7975681ad67b1b6f8d174b57b666f787b801df9511d7a90e90e9af2386f4051669a4763ce5e9720fc8ae2b'.
            'c90e7c33d92a4bcecefddb06599b1f3adf48cde42d442d76c4d938d1570379bf1ab45feae95f94f48a460a8894f90e0208ba9'.
            '3d86b505f32942f53bdab8e506ba227cc813cd26a0ba9a93c46f27dd0c2b7452fd8c79c7aa72b885d95ef6d1dc810829b0832'.
            'abe290d';
    }


    /**
     * Test that signing works.
     */
    public function testSign()
    {
        $this->assertEquals($this->validSig, bin2hex($this->backend->sign($this->privKey, 'Signed text')));
    }


    /**
     * Test signing with something that's not a private key.
     *
     * @expectedException RuntimeException
     */
    public function testSignFailure()
    {
        $k = SymmetricKey::generate(10);
        @$this->backend->sign($k, 'Signed text');
    }


    /**
     * Test the verification of signatures.
     */
    public function testVerify()
    {
        // test successful verification
        $this->assertTrue($this->backend->verify($this->pubKey, 'Signed text', hex2bin($this->validSig)));

        // test forged signature
        $wrongSig = $this->validSig;
        $wrongSig[10] = '6';
        $this->assertFalse($this->backend->verify($this->pubKey, 'Signed text', hex2bin($wrongSig)));
    }


    /**
     * Test encryption.
     */
    public function testEncrypt()
    {
        // test symmetric encryption
        $this->backend->setCipher(Constants::BLOCK_ENC_AES128);
        $this->assertNotEmpty($this->backend->encrypt($this->sharedKey, 'Plaintext'));
        $this->backend->setCipher(Constants::BLOCK_ENC_AES128_GCM);

        // test encryption with public key
        $this->assertNotEmpty($this->backend->encrypt($this->pubKey, 'Plaintext'));

        // test encryption with private key
        $this->assertNotEmpty($this->backend->encrypt($this->privKey, 'Plaintext'));
    }


    /**
     * Test decryption.
     */
    public function testDecrypt()
    {
        // test decryption with symmetric key
        $this->backend->setCipher(Constants::BLOCK_ENC_AES128);
        $this->assertEquals(
            'Plaintext',
            $this->backend->decrypt(
                $this->sharedKey,
                hex2bin('9faa2195bd89d2b8b3721f4fea39e904250096ad2bcd66cf77f8423af83d18ba')
            )
        );
        $this->backend->setCipher(Constants::BLOCK_ENC_AES128_GCM);

        // test decryption with private key
        $this->assertEquals(
            'Plaintext',
            $this->backend->decrypt(
                $this->privKey,
                hex2bin(
                    'c2aa74a85de59daef76c4f4736680ff55503d1ce991a6b947ad5d269b93ef97acf761c1c1ccfedc1382d2c16ea52b7f6b'.
                    '298d8a0f6dbf5e46c41df70804888758e2b95502d9b0849c8d670e4bb9f13bb9afa1d51a76a32625513599c4a2d841cb7'.
                    '9beec171b9c0cf11466e90187e91377a7f7582f3eec3df6703a1abda89339d0f490bca61ceac743be401d861d50eb6aaa'.
                    '2db63264cd2013e4008d82c4e7b3f8f13447cf136e52c9b9f06c062a3fe66d3b9f7fa78281d149e7756a97edb0b2a500f'.
                    '110587f2d81790922def9061c4d8d500cd67ade406b61a20a8fe3b7db1ccc69095a20f556e5ed1f91ccaff1cb3f13065e'.
                    'bee9e20064b0a75edb2b603af6c'
                )
            )
        );

        // test decryption with public key
        $this->assertEquals(
            'Plaintext',
            $this->backend->decrypt(
                $this->pubKey,
                hex2bin(
                    'd012f638b7814f63cce16d1938d34e1f82abcbe925cf579a4dd6e5b0d8f0c524b77a94423625c1cec7cc45e26f37188ff'.
                    '18870cd4f8cd3e0de6084413c71c1f4f14f04858a655162e9332f4b26fe4523cebf7de51267290f8ae290c869fb324570'.
                    'd9065b9604587111b116e8d15d8ef820f2ea2c1ae129ce27a20c4a7e4df815fb47a047cd11b06ada9f4ad8815452380a0'.
                    '9fb6bff787ff167a20662740e1ac034e66612e2194d8b60a22341032d758fd94221314125dbb2d1432b4a3633b0857d8d'.
                    '4938aabe1b53ab5f970fb4ad0ed0a554771cfa819cffba8ec5935a6d2f706dfcada355da34b994691c76a60d10c746a5b'.
                    '683b2a0080d847ff208cf240a1c'
                )
            )
        );
    }


    /**
     * Test for wrong digests.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSetUnknownDigest()
    {
        $backend = new OpenSSL();
        $backend->setDigestAlg('foo');
    }



    /**
     * Test ISO 10126 padding.
     */
    public function testPad()
    {
        $this->assertEquals('666f6f0d0d0d0d0d0d0d0d0d0d0d0d0d', bin2hex($this->backend->pad('foo')));
        $this->assertEquals(
            '666f6f626172666f6f626172666f6f6261720e0e0e0e0e0e0e0e0e0e0e0e0e0e',
            bin2hex($this->backend->pad('foobarfoobarfoobar'))
        );
    }


    /**
     * Test ISO 10126 unpadding.
     */
    public function testUnpad()
    {
        $this->assertEquals('foo', $this->backend->unpad(hex2bin('666f6f0d0d0d0d0d0d0d0d0d0d0d0d0d')));
        $this->assertEquals(
            'foobarfoobarfoobar',
            $this->backend->unpad(hex2bin('666f6f626172666f6f626172666f6f6261720e0e0e0e0e0e0e0e0e0e0e0e0e0e'))
        );
    }


    /**
     * Test for wrong ciphers.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSetUnknownCipher()
    {
        $backend = new OpenSSL();
        $backend->setCipher('foo');
    }
}
