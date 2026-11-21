<?php
declare(strict_types=1);

namespace SecAlert\Source;

use SecAlert\Http;
use SecAlert\Item;

/** RSS 2.0 / Atom feed, optionally filtered by keywords (case-insensitive, matched on title+summary). */
final class FeedSource implements Source
{
    /** @param string[] $keywords empty = accept everything */
    public function __construct(
        private readonly string $name,
        private readonly string $url,
        private readonly array $keywords = [],
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function fetch(\DateTimeImmutable $since): array
    {
        $xml = Http::get($this->url);
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        libxml_use_internal_errors($prev);
        if ($doc === false) {
            throw new \RuntimeException("Invalid XML from {$this->url}");
        }
        $entries = [];
        foreach ($doc->channel->item ?? [] as $e) { // RSS
            $entries[] = [(string) $e->title, (string) $e->link, (string) $e->pubDate, (string) $e->description, (string) ($e->guid ?? '')];
        }
        foreach ($doc->entry ?? [] as $e) { // Atom
            $link = '';
            foreach ($e->link as $l) {
                $link = (string) $l['href'];
                if ((string) $l['rel'] !== 'alternate' && (string) $l['rel'] !== '') {
                    continue;
                }
                break;
            }
            $entries[] = [(string) $e->title, $link, (string) ($e->published ?: $e->updated), (string) ($e->summary ?: $e->content), (string) $e->id];
        }

        $items = [];
        foreach ($entries as [$title, $link, $date, $summary, $guid]) {
            try {
                $pub = new \DateTimeImmutable($date ?: 'now');
            } catch (\Exception) {
                continue;
            }
            if ($pub < $since || !$this->matches($title . ' ' . $summary)) {
                continue;
            }
            $items[] = new Item(
                id: $guid !== '' ? $guid : $link,
                source: $this->name,
                title: trim(html_entity_decode($title)),
                url: trim($link),
                published: $pub,
                summary: self::clean($summary),
            );
        }
        return $items;
    }

    private function matches(string $text): bool
    {
        if ($this->keywords === []) {
            return true;
        }
        foreach ($this->keywords as $k) {
            if (stripos($text, $k) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function clean(string $html): string
    {
        $t = trim(preg_replace('/\s+/', ' ', strip_tags(html_entity_decode($html))) ?? '');
        return mb_strlen($t) > 400 ? mb_substr($t, 0, 400) . '…' : $t;
    }
}
