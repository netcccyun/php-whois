<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Factory;

class DomainHelper
{
    /**
     * @param string $a
     * @param string $b
     * @return bool
     */
    public static function compareNames($a, $b)
    {
        $a = self::toAscii($a);
        $b = self::toAscii($b);
        // Two invalid (unconvertible) names must not be considered equal
        return $a !== '' && $a === $b;
    }
    
    /**
     * @param string $domain
     * @return string
     */
    public static function toAscii($domain)
    {
        if (!is_string($domain)) {
            return "";
        }
        if (empty($domain) || strlen($domain) >= 255) {
            return "";
        }
        $cor = self::correct($domain);
        if ($cor === '') {
            return "";
        }
        // idn_to_ascii() returns false on failure; always return a string (callers use strict_types)
        $res = idn_to_ascii($cor, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        return is_string($res) ? $res : "";
    }

    /**
     * @param string $domain
     * @return string
     */
    public static function toUnicode($domain)
    {
        if (!is_string($domain) || empty($domain) || strlen($domain) >= 255) {
            return "";
        }
        $cor = self::correct($domain);
        if ($cor === '') {
            return "";
        }
        $res = idn_to_utf8($cor, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        return is_string($res) ? $res : "";
    }

    /**
     * @param string $domain
     * @return string
     */
    public static function filterAscii($domain)
    {
        if (!is_string($domain) || empty($domain) || strlen($domain) >= 255) {
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
