<?php
declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use SecAlert\Item;
use SecAlert\Report;

$n = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$r = new Report([
    new Item('1', 'NVD', 'CVE-2099-0001 (PHP)', 'https://nvd.nist.gov/x', $n, 'a <b> & c', 'CRITICAL', 9.8),
    new Item('2', 'Feed', 'News', 'javascript:alert(1)', $n),
]);
assert(!$r->isEmpty());
assert(str_contains($r->subject(), '高風險 1'));
assert(!str_contains($r->html(), '<b> &'), 'html must be escaped');
assert(!str_contains($r->html(), 'javascript:'), 'unsafe URL must be neutralised');
assert(strpos($r->text(), 'CVE-2099-0001') < strpos($r->text(), 'News'), 'severity sorted first');
assert((new Report([]))->subject() !== "" && str_contains((new Report([]))->text(), "運作正常"));
echo "OK\n";
