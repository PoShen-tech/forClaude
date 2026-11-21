#!/usr/bin/env php
<?php
declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use SecAlert\Report;
use SecAlert\SmtpMailer;
use SecAlert\Source\FeedSource;
use SecAlert\Source\NvdSource;

$env = static fn(string $k, string $d = ''): string => ($v = getenv($k)) === false || $v === '' ? $d : $v;
$dryRun = in_array('--dry-run', $argv, true);

$lookback = (int) $env('LOOKBACK_HOURS', '26'); // 每日執行 + 2 小時重疊緩衝
$since = new DateTimeImmutable("-{$lookback} hours", new DateTimeZone('UTC'));
$kw = ['apache', 'httpd', 'php', 'mod_', 'xampp', 'laravel', 'wordpress core'];

$sources = [
    new NvdSource($env('NVD_API_KEY') ?: null),
    new FeedSource('PHP.net', 'https://www.php.net/releases/feed.php'),
    new FeedSource('PHP.net News', 'https://www.php.net/feed.atom', ['security', 'vulnerab', 'cve', 'release']),
    new FeedSource('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews', $kw),
    new FeedSource('BleepingComputer', 'https://www.bleepingcomputer.com/feed/', $kw),
    new FeedSource('SecurityWeek', 'https://www.securityweek.com/feed/', $kw),
];

$items = [];
$errors = [];
foreach ($sources as $s) {
    try {
        array_push($items, ...$s->fetch($since));
    } catch (Throwable $t) {
        $errors[] = $s->name() . ': ' . $t->getMessage();
        fwrite(STDERR, "[warn] {$s->name()}: {$t->getMessage()}\n");
    }
}

// 去重（同 id 或同網址）
$seen = [];
$items = array_values(array_filter($items, function ($i) use (&$seen) {
    $k = strtolower($i->url ?: $i->id);
    return isset($seen[$k]) ? false : ($seen[$k] = true);
}));

$report = new Report($items, $errors);
echo $report->subject(), "\n";

if ($dryRun) {
    echo $report->text(), "\n";
    exit(0);
}
if ($report->isEmpty() && $env('SEND_EMPTY', '0') !== '1') {
    echo "沒有新項目，不寄信。\n";
    exit($errors && count($errors) === count($sources) ? 1 : 0);
}

$to = array_values(array_filter(array_map('trim', explode(',', $env('MAIL_TO')))));
if (!$to) {
    fwrite(STDERR, "MAIL_TO 未設定\n");
    exit(2);
}
$user = trim($env('SMTP_USER'));
$pass = preg_replace('/\s+/', '', $env('SMTP_PASS')); // 應用程式密碼常帶空格/換行
$mailer = new SmtpMailer($env('SMTP_HOST', 'smtp.gmail.com'), (int) $env('SMTP_PORT', '587'), $user, $pass, $env('MAIL_FROM', $user));
fwrite(STDERR, sprintf("SMTP user length=%d, pass length=%d (應用程式密碼應為 16)\n", strlen($user), strlen($pass)));
$mailer->send($to, $report->subject(), $report->html(), $report->text());
echo "已寄出至 " . implode(', ', $to) . "\n";
