<?php
declare(strict_types=1);

namespace SecAlert\Source;

use SecAlert\Item;

interface Source
{
    public function name(): string;

    /** @return Item[] items published at or after $since */
    public function fetch(\DateTimeImmutable $since): array;
}
