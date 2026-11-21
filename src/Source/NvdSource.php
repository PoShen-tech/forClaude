<?php
declare(strict_types=1);

namespace SecAlert\Source;

use SecAlert\Http;
use SecAlert\Item;

/** NVD CVE API 2.0: CVEs published since $since affecting Apache httpd / PHP (CPE match). */
final class NvdSource implements Source
{
    private const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    private const CPES = [
        'Apache HTTP Server' => 'cpe:2.3:a:apache:http_server',
        'PHP' => 'cpe:2.3:a:php:php',
    ];

    public function __construct(private readonly ?string $apiKey = null)
    {
    }

    public function name(): string
    {
        return 'NVD';
    }

    public function fetch(\DateTimeImmutable $since): array
    {
        $utc = new \DateTimeZone('UTC');
        $fmt = 'Y-m-d\TH:i:s.000\Z';
        $items = [];
        $first = true;
        foreach (self::CPES as $product => $cpe) {
            if (!$first) {
                sleep($this->apiKey ? 1 : 7); // NVD rate limit: 5 req/30s without key
            }
            $first = false;
            $query = http_build_query([
                'virtualMatchString' => $cpe,
                'pubStartDate' => $since->setTimezone($utc)->format($fmt),
                'pubEndDate' => (new \DateTimeImmutable('now', $utc))->format($fmt),
            ]);
            $headers = $this->apiKey ? ['apiKey: ' . $this->apiKey] : [];
            $data = json_decode(Http::get(self::API . '?' . $query, $headers), true, 512, JSON_THROW_ON_ERROR);
            foreach ($data['vulnerabilities'] ?? [] as $v) {
                $items[] = $this->toItem($v['cve'], $product);
            }
        }
        return $items;
    }

    private function toItem(array $cve, string $product): Item
    {
        $desc = '';
        foreach ($cve['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') {
                $desc = $d['value'];
                break;
            }
        }
        $score = null;
        $severity = null;
        foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $k) {
            if (!empty($cve['metrics'][$k][0]['cvssData'])) {
                $m = $cve['metrics'][$k][0];
                $score = (float) $m['cvssData']['baseScore'];
                $severity = $m['cvssData']['baseSeverity'] ?? $m['baseSeverity'] ?? null;
                break;
            }
        }
        $id = $cve['id'];
        return new Item(
            id: $id,
            source: 'NVD',
            title: $id . ' (' . $product . ')',
            url: 'https://nvd.nist.gov/vuln/detail/' . $id,
            published: new \DateTimeImmutable($cve['published'] . 'Z'),
            summary: $desc,
            severity: $severity,
            score: $score,
            tags: [$product, 'CVE'],
        );
    }
}
