<?php

namespace RobRichards\XMLSecLibs\Utils;

class XPath
{
    public const ALPHANUMERIC = '\w\d';
    public const NUMERIC = '\d';
    public const LETTERS = '\w';
    public const EXTENDED_ALPHANUMERIC = '\w\d\s\-_:\.';

    public const SINGLE_QUOTE = '\'';
    public const DOUBLE_QUOTE = '"';
    public const ALL_QUOTES = '[\'"]';


    /**
     * Filter an attribute value for save inclusion in an XPath query.
     *
     * @param string $value The value to filter.
     * @param string $quotes The quotes used to delimit the value in the XPath query.
     *
     * @return string The filtered attribute value.
     */
    public static function filterAttrValue($value, $quotes = self::ALL_QUOTES)
    {
        return preg_replace('#' . $quotes . '#', '', $value);
    }


    /**
     * Filter an attribute name for save inclusion in an XPath query.
     *
     * @param string $name The attribute name to filter.
     * @param mixed $allow The set of characters to allow. Can be one of the constants provided by this class, or a
     * custom regex excluding the '#' character (used as delimiter).
     *
     * @return string The filtered attribute name.
     */
    public static function filterAttrName($name, $allow = self::EXTENDED_ALPHANUMERIC)
    {
        return preg_replace('#[^' . $allow . ']#', '', $name);
    }
}
