<?php

namespace SimpleSAML\XMLSec\Exception;

/**
 * Class UnparseableXmlException
 *
 * This exception is thrown when an XML document cannot be parsed.
 *
 * @package SimpleSAML\XMLSec\Exception
 */
final class UnparseableXmlException extends RuntimeException
{
    private static $levelMap = array(
        LIBXML_ERR_WARNING => 'WARNING',
        LIBXML_ERR_ERROR   => 'ERROR',
        LIBXML_ERR_FATAL   => 'FATAL'
    );

    public function __construct(\LibXMLError $error)
    {
        $message = sprintf(
            'Unable to parse XML - "%s[%d]": "%s" in "%s" at line %d on column %d"',
            static::$levelMap[$error->level],
            $error->code,
            $error->message,
            $error->file ?: '(string)',
            $error->line,
            $error->column
        );

        parent::__construct($message);
    }
}
