<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Factory;

/**
 * Immutable data object
 */
class TldServer
{
    /** @var int */
    private static $counter = 0;

    /**
     * @param array $data
     * @param TldParser $defaultParser
     * @return TldServer
     */
    public static function fromData($data, ?TldParser $defaultParser = null)
    {
        return Factory::get()->createTldSever($data, $defaultParser);
    }

    /**
     * @param array $dataList
     * @param TldParser $defaultParser
     * @return TldServer[]
     */
    public static function fromDataList($dataList, ?TldParser $defaultParser = null)
    {
        return Factory::get()->createTldSevers($dataList, $defaultParser);
    }

    /**
     * @param string $zone Must starts from '.'
     * @param string $host
     * @param bool $centralized
     * @param TldParser $parser
     * @param string $queryFormat
     */
    public function __construct($zone, $host, $centralized, ?TldParser $parser, $queryFormat = null, $rdap = false)
    {
        $this->uid = ++self::$counter;
        $this->zone = strval($zone);
        if (empty($this->zone)) {
            throw new InvalidArgumentException("Zone must be specified");
        }
        $this->zone = ($this->zone[0] == '.') ? $this->zone : ".{$this->zone}";
        $this->inverseZoneParts = array_reverse(explode('.', $this->zone));
        array_pop($this->inverseZoneParts);

        $this->host = strval($host);
        if (empty($this->host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        $this->centralized = (bool)$centralized;
        $this->parser = $parser;
        $this->queryFormat = !empty($queryFormat) ? strval($queryFormat) : "%s\r\n";
        $this->rdap = (bool)$rdap;
        if ($this->rdap) {
            $this->parser = Factory::get()->createTldParser(TldParser::RDAP);
        }
    }

    /** @var string */
    protected $uid;

    /** @var string */
    protected $zone;

    /** @var string[] */
    protected $inverseZoneParts;

    /** @var bool */
    protected $centralized;

    /** @var string */
    protected $host;

    /** @var TldParser */
    protected $parser;

    /** @var string */
    protected $queryFormat;

    /** @var bool */
    protected $rdap;

    /**
     * @return string
     */
    public function getId()
    {
        return $this->uid;
    }

    /**
     * @return bool
     */
    public function isCentralized()
    {
        return (bool)$this->centralized;
    }

    /**
     * @param string $domain
     * @return bool
     */
    public function isDomainZone($domain)
    {
        return $this->matchDomainZone($domain) > 0;
    }

    /**
     * @param string $domain
     * @return int
     */
    public function matchDomainZone($domain)
    {
        $domainParts = explode('.', $domain);
        if ($this->zone === '.' && count($domainParts) === 1) {
            return 1;
        }
        array_shift($domainParts);
        $domainCount = count($domainParts);
        $zoneCount = count($this->inverseZoneParts);
        if (count($domainParts) < $zoneCount) {
            return 0;
        }
        $i = -1;
        while (++$i < $zoneCount) {
            $zonePart = $this->inverseZoneParts[$i];
            $domainPart = $domainParts[$domainCount - $i - 1];
            if ($zonePart != $domainPart && $zonePart != '*') {
                return 0;
            }
        }
        return $zoneCount;
    }

    /**
     * @return string
     */
    public function getZone()
    {
        return $this->zone;
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @return TldParser
     */
    public function getParser()
    {
        return $this->parser;
    }

    /**
     * @return string
     */
    public function getQueryFormat()
    {
        return $this->queryFormat;
    }

    /**
     * @return bool
     */
    public function isRdap()
    {
        return (bool)$this->rdap;
    }

    /**
     * @param string $domain
     * @param bool $strict
     * @return string
     */
    public function buildDomainQuery($domain, $strict = false)
    {
        $query = sprintf($this->queryFormat, $domain);
        return $strict ? "=$query" : $query;
    }

    /**
     * @param string $domain
     * @return array
     */
    public function getRdapData($domain)
    {
        $domain = strtolower(trim($domain));
        if (substr($this->host, -1) !== '/') {
            $this->host .= '/';
        }
        $url = $this->host . 'domain/' . urlencode($domain);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, "PHP RDAP Client");
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/rdap+json',
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($ch);
        $errstr = curl_error($ch);
        $errno = curl_errno($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($errno) {
            throw new ConnectionException($errstr, $errno);
        }

        return [$httpCode, $result];
    }
}
