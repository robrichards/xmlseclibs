<?php

namespace RobRichards\XMLSecLibs\Utils;

class XPath
{
    /** @var string */
    public const ALPHANUMERIC = '\w\d';

    /** @var string */
    public const NUMERIC = '\d';

    /** @var string */
    public const LETTERS = '\w';

    /** @var string */
    public const EXTENDED_ALPHANUMERIC = '\w\d\s\-_:\.';

    /** @var string */
    public const SINGLE_QUOTE = '\'';

    /** @var string */
    public const DOUBLE_QUOTE = '"';

    /** @var string */
    public const ALL_QUOTES = '[\'"]';


    /**
     * Filter an attribute value for save inclusion in an XPath query.
     *
     * @param string $value The value to filter.
     * @param string $quotes The quotes used to delimit the value in the XPath query.
     *
     * @return string The filtered attribute value.
     */
    public static function filterAttrValue(string $value, string $quotes = self::ALL_QUOTES): string
    {
        return preg_replace('#' . $quotes . '#', '', $value);
    }


    /**
     * Filter an attribute name for save inclusion in an XPath query.
     *
     * @param string $name The attribute name to filter.
     * @param string $allow The set of characters to allow. Can be one of the constants provided by this class, or a
     *   custom regex excluding the '#' character (used as delimiter).
     *
     * @return string The filtered attribute name.
     */
    public static function filterAttrName(string $name, string $allow = self::EXTENDED_ALPHANUMERIC): string
    {
        return preg_replace('#[^' . $allow . ']#', '', $name);
    }
}
