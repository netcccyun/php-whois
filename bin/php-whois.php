<?php

declare(strict_types=1);

use Iodev\Whois\Factory;
use Iodev\Whois\Helpers\DomainHelper;

// Works on Windows paths too and when installed as a composer dependency (vendor/<vendor>/<package>/bin)
foreach ([__DIR__ . '/../vendor/autoload.php', __DIR__ . '/../../../autoload.php'] as $autoloadFile) {
    if (is_file($autoloadFile)) {
        require $autoloadFile;
        break;
    }
}

function main($argv)
{
    $action = trim($argv[1] ?? '');
    $args = array_slice($argv, 2);

    if (empty($action)) {
        $action = 'help';
    }
    switch (mb_strtolower(ltrim($action, '-'))) {
        case 'help':
        case 'h':
            help();
            return;
    }
    if (in_array($action, ['lookup', 'info'], true) && empty($args[0])) {
        echo "Domain is required for action: {$action}\n";
        exit(1);
    }
    switch ($action) {
        case 'lookup':
            lookup($args[0]);
            break;

        case 'info':
            $opts = parseOpts(implode(' ', array_slice($args, 1)));
            info($args[0], $opts);
            break;

        default:
            echo "Unknown action: {$action}\n";
            exit(1);
    }
}

function parseOpts(string $str): array
{
    $result = [];
    $rest = trim($str);
    while (preg_match('~--([-_a-z\d]+)(\s+|=)(\'([^\']+)\'|[^-\s]+)~ui', $rest, $m, PREG_OFFSET_CAPTURE)) {
        $result[$m[1][0]] = $m[4][0] ?? $m[3][0];
        // PREG_OFFSET_CAPTURE offsets are in bytes, so byte-based substr/strlen must be used
        $rest = trim((string)substr($rest, $m[0][1] + strlen($m[0][0])));
    }
    return $result;
}

function help()
{
    echo implode("\n", [
        'Welcome to php-whois CLI',
        '',
        '  Syntax:',
        '    php-whois {action} [arg1 arg2 ... argN]',
        '    php-whois help|--help|-h',
        '    php-whois lookup {domain}',
        '    php-whois info {domain} [--parser {type}] [--host {whois}]',
        '',
        '  Examples',
        '    php-whois lookup google.com',
        '    php-whois info google.com',
        '    php-whois info google.com --parser block',
        '    php-whois info ya.ru --host whois.nic.ru --parser auto',
        '',
        '',
    ]);
}

function lookup(string $domain)
{
    echo implode("\n", [
        '  action: lookup',
        "  domain: '{$domain}'",
        '',
        '',
    ]);

    $whois = Factory::get()->createWhois();
    $result = $whois->lookupDomain($domain);

    var_dump($result);
}

function info(string $domain, array $options = [])
{
    $options = array_replace([
        'host' => null,
        'parser' => null,
        'file' => null,
    ], $options);

    echo implode("\n", [
        '  action: info',
        "  domain: '{$domain}'",
        sprintf("  options: %s", json_encode($options, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)),
        '',
        '',
    ]);

    $loader = null;
    if ($options['file']) {
        $loader = new \Iodev\Whois\Loaders\FakeSocketLoader();
        $loader->text = file_get_contents($options['file']);
    }

    $tld = Factory::get()->createWhois($loader)->getTldModule();
    $domain = DomainHelper::toAscii($domain);
    $servers = $tld->matchServers($domain);

    if (!empty($options['host'])) {
        $host = $options['host'];
        $filteredServers = array_filter($servers, function (\Iodev\Whois\Modules\Tld\TldServer $server) use ($host) {
            return $server->getHost() == $host;
        });
        if (count($filteredServers) == 0 && count($servers) > 0) {
            $filteredServers = [$servers[0]];
        }
        $servers = array_map(function (\Iodev\Whois\Modules\Tld\TldServer $server) use ($host) {
            return new \Iodev\Whois\Modules\Tld\TldServer(
                $server->getZone(),
                $host,
                $server->isCentralized(),
                $server->getParser(),
                $server->getQueryFormat(),
                $server->isRdap()
            );
        }, $filteredServers);
    }

    if (!empty($options['parser'])) {
        try {
            $parser = Factory::get()->createTldParser($options['parser']);
        } catch (\Throwable $e) {
            echo "\nCannot create TLD parser with type '{$options['parser']}'\n\n";
            throw $e;
        }
        $servers = array_map(function (\Iodev\Whois\Modules\Tld\TldServer $server) use ($parser) {
            return new \Iodev\Whois\Modules\Tld\TldServer(
                $server->getZone(),
                $server->getHost(),
                $server->isCentralized(),
                $parser,
                $server->getQueryFormat(),
                $server->isRdap()
            );
        }, $servers);
    }

    [, $info] = $tld->loadDomainData($domain, $servers);

    var_dump($info);
}

main($argv);


