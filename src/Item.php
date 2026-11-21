<?php
declare(strict_types=1);

namespace SecAlert;

final class Item
{
    public function __construct(
        public readonly string $id,
        public readonly string $source,
        public readonly string $title,
        public readonly string $url,
        public readonly \DateTimeImmutable $published,
        public readonly string $summary = '',
        public readonly ?string $severity = null,
        public readonly ?float $score = null,
        /** @var string[] */
        public readonly array $tags = [],
    ) {
    }
}
