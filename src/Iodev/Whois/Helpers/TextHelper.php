<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

class TextHelper
{
    /**
     * @param string $text
     * @return string
     */
    public static function toUtf8($text)
    {
        $srcEncoding = mb_detect_encoding($text);
        if (!empty($srcEncoding) && strtolower($srcEncoding) !== 'utf-8') {
            return mb_convert_encoding($text, 'utf-8', strtolower($srcEncoding));
        }
        if (mb_check_encoding($text, 'utf-8')) {
            return $text;
        }
        // iconv() returns false on undefined bytes - never return false where a string is expected
        if (mb_check_encoding($text, 'windows-1252')) {
            $converted = @iconv('windows-1252', 'utf-8', $text);
            if ($converted !== false) {
                return $converted;
            }
        }
        if (mb_check_encoding($text, 'windows-1251')) {
            $converted = @iconv('windows-1251', 'utf-8', $text);
            if ($converted !== false) {
                return $converted;
            }
        }
        return $text;
    }
}
