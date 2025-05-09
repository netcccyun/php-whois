<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Factory;

class DomainHelper
{
    /**
     * @param string $a
     * @param string $b
     * @return string
     */
    public static function compareNames($a, $b)
    {
        $a = self::toAscii($a);
        $b = self::toAscii($b);
        return ($a == $b);
    }
    
    /**
     * @param string $domain
     * @return string
     */
    public static function toAscii($domain)
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return "";
        }
        $cor = self::correct($domain);
        return idn_to_ascii($cor);
    }
    
    /**
     * @param string $domain
     * @return string
     */
    public static function toUnicode($domain)
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return "";
        }
        $cor = self::correct($domain);
        return idn_to_utf8($cor);
    }

    /**
     * @param string $domain
     * @return string
     */
    public static function filterAscii($domain)
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return "";
        }
        $domain = self::correct($domain);
        // Pick first part before space
        $domain = explode(" ", $domain)[0];
        // All symbols must be valid
        if (preg_match('~[^-.\da-z]+~ui', $domain)) {
            return "";
        }
        return $domain;
    }

    /**
     * @param string $domain
     * @return string
     */
    private static function correct($domain)
    {
        $domain = trim($domain);
        // Fix for .UZ whois response
        while (preg_match('~\bnot\.defined\.?\b~ui', $domain)) {
            $domain = preg_replace('~\bnot\.defined\.?\b~ui', '', $domain);
        }
        return rtrim(preg_replace('~\s*\.\s*~ui', '.', $domain), ".-\t ");
    }
}
