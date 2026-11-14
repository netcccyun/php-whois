<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Modules\Tld\TldParser;

class RdapParser extends TldParser
{

    /**
     * @return string
     */
    public function getType()
    {
        return TldParser::RDAP;
    }

    /**
     * @param array $cfg
     * @return $this
     */
    public function setConfig($cfg)
    {
        foreach ($cfg as $k => $v) {
            $this->{$k} = $v;
        }
        return $this;
    }

    /**
     * @param TldResponse $response
     * @return TldInfo
     */
    public function parseResponse(TldResponse $response)
    {
        if ($response->httpCode != 200 || !$response->text) {
            return null;
        }
        $arr = json_decode($response->text, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($arr)) {
            return null;
        }

        $nameServers = [];
        if (!empty($arr['nameservers']) && is_array($arr['nameservers'])) {
            foreach ($arr['nameservers'] as $ns) {
                if (!empty($ns['ldhName']) && is_string($ns['ldhName'])) {
                    $name = strtolower(rtrim($ns['ldhName'], '.'));
                    if (!in_array($name, $nameServers, true)) {
                        $nameServers[] = $name;
                    }
                }
            }
        }
        $dnssec = isset($arr['secureDNS']['delegationSigned']) && $arr['secureDNS']['delegationSigned'] ? 'signedDelegation' : 'unsigned';
        $creationDate = 0;
        $expirationDate = 0;
        $updatedDate = 0;
        if (isset($arr['events']) && is_array($arr['events'])) {
            foreach ($arr['events'] as $event) {
                // eventDate may be missing; strtotime(null) is a TypeError under strict_types, false is not an int
                if (!isset($event['eventAction'], $event['eventDate']) || !is_string($event['eventDate'])) {
                    continue;
                }
                $time = (int)strtotime($event['eventDate']);
                if ($event['eventAction'] == 'registration') {
                    $creationDate = $time;
                } elseif ($event['eventAction'] == 'expiration') {
                    $expirationDate = $time;
                } elseif ($event['eventAction'] == 'last changed') {
                    $updatedDate = $time;
                }
            }
        }
        $states = isset($arr['status']) && is_array($arr['status']) ? array_values($arr['status']) : [];

        $registrantName = '';
        $registrarName = '';
        if (isset($arr['entities']) && is_array($arr['entities'])) {
            foreach ($arr['entities'] as $entity) {
                if (isset($entity['roles']) && is_array($entity['roles'])) {
                    if (in_array('registrant', $entity['roles'])) {
                        $registrantName = $this->getVcardName($entity);
                    }
                    if (in_array('registrar', $entity['roles'])) {
                        $registrarName = $this->getVcardName($entity);
                    }
                }
            }
        }

        $data = [
            "parserType" => $this->getType(),
            "domainName" => strtolower(is_string($arr['ldhName'] ?? null) ? $arr['ldhName'] : ''),
            "whoisServer" => '',
            "nameServers" => $nameServers,
            "dnssec" => $dnssec,
            "creationDate" => $creationDate,
            "expirationDate" => $expirationDate,
            "updatedDate" => $updatedDate,
            "owner" => $registrantName,
            "registrar" => $registrarName,
            "states" => $states,
        ];
        $info = new TldInfo($response, $data);
        return $info;
    }

    private function getVcardName($entity)
    {
        if (isset($entity['vcardArray'][1]) && is_array($entity['vcardArray'][1])) {
            foreach ($entity['vcardArray'][1] as $vcardItem) {
                if (isset($vcardItem[0], $vcardItem[3]) && $vcardItem[0] === 'fn' && is_string($vcardItem[3])) {
                    return $vcardItem[3];
                }
            }
        }
        return '';
    }
}
