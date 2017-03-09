<?php

namespace RobRichards\XMLSecLibs\Tests;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;
use DOMDocument;
use DOMNode;

/**
 *
 * @coversDefaultClass RobRichards\XMLSecLibs\XMLSecEnc
 * @author Jelle Vink <jelle.vink@gmail.com>
 *
 */
class XMLSecEncTest extends TestCase
{
    /**
     * Basic encryption
     * (taken from xmlsec-encrypt.phpt)
     *
     * @param string $source Source filename
     * @param string $keyType Security key type
     *
     * @dataProvider providerTestBasicEncryptDecrypt
     * @group functional
     */
    public function testBasicEncrypt($source, $keyType)
    {
        $dom = new DOMDocument();
        $dom->load($source);

        $objKey = new XMLSecurityKey($keyType);
        $objKey->generateSessionKey();

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($this->createSiteKey(), $objKey);

        $enc->type = XMLSecEnc::Element;
        $encNode = $enc->encryptNode($objKey);

        $this->assertSame('EncryptedData', $dom->documentElement->localName);
        $this->assertSame('EncryptedData', $encNode->localName);
        $this->assertSame(XMLSecEnc::XMLENCNS, $encNode->namespaceURI);
    }

    /**
     * Basic encryption content
     * (taken from xmlsec-encrypt-content.phpt)
     *
     * @param string $source Source filename
     * @param string $keyType Security key type
     *
     * @dataProvider providerTestBasicEncryptDecrypt
     * @group functional
     */
    public function testBasicEncryptContent($source, $keyType)
    {
        $dom = new DOMDocument();
        $dom->load($source);

        $objKey = new XMLSecurityKey($keyType);
        $objKey->generateSessionKey();

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($this->createSiteKey(), $objKey);

        $enc->type = XMLSecEnc::Content;
        $encNode = $enc->encryptNode($objKey);

        $this->assertSame('Root', $dom->documentElement->localName);
        $this->assertSame('EncryptedData', $encNode->localName);
        $this->assertSame(XMLSecEnc::XMLENCNS, $encNode->namespaceURI);
    }

    /**
     * Basic encryption content without modifying original data
     * (taken from xmlsec-encrypt-noreplace.phpt)
     *
     * @param string $source Source filename
     * @param string $keyType Security key type
     *
     * @dataProvider providerTestBasicEncryptDecrypt
     * @group functional
     */
    public function testBasicEncryptNoModify($source, $keyType)
    {
        $dom = new DOMDocument();
        $dom->load($source);
        $origData = $dom->saveXML();

        $objKey = new XMLSecurityKey($keyType);
        $objKey->generateSessionKey();

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($this->createSiteKey(), $objKey);

        $enc->type = XMLSecEnc::Element;
        $encNode = $enc->encryptNode($objKey, false);

        $this->assertSame($origData, $dom->saveXML());
        $this->assertSame('EncryptedData', $encNode->localName);
        $this->assertSame(XMLSecEnc::XMLENCNS, $encNode->namespaceURI);
    }

    /**
     * Basic decryption content
     * (taken from xmlsec-decrypt-content.phpt)
     *
     * @param string $source Source filename
     * @param string $keyType Security key type
     * @param string $encrypted Encrypted filename
     *
     * @dataProvider providerTestBasicEncryptDecrypt
     * @group functional
     */
    public function testBasicDecrypt($source, $keyType, $encrypted)
    {
        $doc = new DOMDocument();
        $doc->load($encrypted);

        $objenc = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");

        $objKey = $objenc->locateKey();
        $key = null;

        if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
            if ($objKeyInfo->isEncrypted) {
                $objencKey = $objKeyInfo->encryptedCtx;
                $objKeyInfo->loadKey($this->getFixtureFileName('privkey.pem', true), true);
                $key = $objencKey->decryptKey($objKeyInfo);
            }
        }

        if (empty($objKey->key)) {
            $objKey->loadKey($key);
        }

        if ($decrypt = $objenc->decryptNode($objKey, true)) {
            $output = null;
            if ($decrypt instanceof DOMNode) {
                if ($decrypt instanceof DOMDocument) {
                    $output = $decrypt->saveXML();
                } else {
                    $output = $decrypt->ownerDocument->saveXML();
                }
            } else {
                $output = $decrypt;
            }
        }

        $resDoc = new DOMDocument();
        $resDoc->load($source);
        $res = $resDoc->saveXML();

        $this->assertSame($res, $output);
    }

    /**
     * Create site key
     * @return XMLSecurityKey
     */
    protected function createSiteKey()
    {
        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
        $siteKey->loadKey($this->getFixtureFileName('mycert.pem', true), true, true);
        return $siteKey;
    }

    public function providerTestBasicEncryptDecrypt()
    {
        return array(

            // legacy fixtures
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::AES256_CBC,
                $this->getFixtureFileName('oaep_sha1-res.xml', true),
            ),
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::AES256_CBC,
                $this->getFixtureFileName('oaep_sha1-content-res.xml', true),
            ),

            // new fixtures
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::TRIPLEDES_CBC,
                $this->getFixtureFileName('basic-doc-encrypted-tripledes-cbc.xml'),
            ),
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::AES128_CBC,
                $this->getFixtureFileName('basic-doc-encrypted-aes128-cbc.xml'),
            ),
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::AES192_CBC,
                $this->getFixtureFileName('basic-doc-encrypted-aes192-cbc.xml'),
            ),
            array(
                $this->getFixtureFileName('basic-doc.xml', true),
                XMLSecurityKey::AES256_CBC,
                $this->getFixtureFileName('basic-doc-encrypt-aes256-cbc.xml'),
            ),
        );
    }

    /**
     * @covers ::encryptNode
     * @group unit
     * @expectedException Exception
     * @expectedExceptionMessage Node to encrypt has not been set
     */
    public function testEncryptNodeRequiresNode()
    {
        $sut = new XMLSecEnc();
        $sut->encryptNode(null);
    }

    /**
     * @covers ::encryptNode
     * @group unit
     * @expectedException Exception
     * @expectedExceptionMessage Invalid Key
     */
    public function testEncryptNodeInvalidKey()
    {
        $sut = new XMLSecEnc();
        $sut->setNode(new DOMNode());
        $sut->encryptNode(null);
    }
}
