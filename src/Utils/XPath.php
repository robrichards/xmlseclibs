<?php

namespace RobRichards\XMLSecLibs\Utils;

class XPath
{
    const ALPHANUMERIC = 0;
    const NUMERIC = 1;
    const LETTERS = 2;
    const EXTENDED_ALPHANUMERIC = 3;

    private static $regex = [
        self::ALPHANUMERIC => '#[^\w\d]#',
        self::NUMERIC => '#[^\d]#',
        self::LETTERS => '#[^\w]#',
        self::EXTENDED_ALPHANUMERIC => '/[^\w\d\s-_:]/'
    ];


    /**
     * Filter a string for save inclusion in an XPath query.
     *
     * @param string $input The query parameter to filter.
     * @param int $allow The character set that we should allow.
     *
     * @return string The input filtered with only allowed characters.
     */
    public static function filter($input, $allow = self::EXTENDED_ALPHANUMERIC)
    {
        return preg_replace(self::$regex[$allow], '', $input);
    }
}
