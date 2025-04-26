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
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        $nameServers = [];
        if (!empty($arr['nameservers'])) {
            foreach ($arr['nameservers'] as $ns) {
                if (!empty($ns['ldhName']) && !in_array($ns['ldhName'], $nameServers)) {
                    $nameServers[] = $ns['ldhName'];
                }
            }
        }
        $dnssec = isset($arr['secureDNS']['delegationSigned']) && $arr['secureDNS']['delegationSigned'] ? 'signedDelegation' : 'unsigned';
        $creationDate = 0;
        $expirationDate = 0;
        $updatedDate = 0;
        foreach ($arr['events'] as $event) {
            if (isset($event['eventAction'])) {
                if ($event['eventAction'] == 'registration') {
                    $creationDate = strtotime($event['eventDate']);
                } elseif ($event['eventAction'] == 'expiration') {
                    $expirationDate = strtotime($event['eventDate']);
                } elseif ($event['eventAction'] == 'last changed') {
                    $updatedDate = strtotime($event['eventDate']);
                }
            }
        }
        $states = $arr['status'] ?? [];

        $registrantName = null;
        $registrarName = null;
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
            "domainName" => strtolower($arr['ldhName'] ?? ''),
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
                if (isset($vcardItem[0]) && $vcardItem[0] === 'fn') {
                    return $vcardItem[3];
                }
            }
        }
        return null;
    }
}
