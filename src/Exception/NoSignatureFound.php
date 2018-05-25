<?php

namespace SimpleSAML\XMLSec\Exception;

/**
 * Class NoSignatureFound
 *
 * This exception is thrown when we can't find a signature in a given DOM document or element.
 *
 * @package SimpleSAML\XMLSec\Exception
 */
class NoSignatureFound extends RuntimeException
{

    protected $message = "There is no signature in the document or element.";
}
