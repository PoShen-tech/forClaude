<?php
declare(strict_types=1);

namespace SecAlert;

final class Report
{
    /** @param Item[] $items */
    public function __construct(private readonly array $items, private readonly array $errors = [])
    {
    }

    public function isEmpty(): bool
    {
        return $this->items === [];
    }

    public function subject(): string
    {
        if ($this->items === []) {
            return '[資安快報] ' . date('Y-m-d') . ' 今日無新的 Apache/PHP 漏洞（系統運作正常）';
        }
        $crit = count(array_filter($this->items, fn(Item $i) => in_array($i->severity, ['CRITICAL', 'HIGH'], true)));
        $s = sprintf('[資安快報] Apache/PHP 新漏洞與新聞 %s：%d 則', date('Y-m-d'), count($this->items));
        return $crit > 0 ? "{$s}（高風險 {$crit}）" : $s;
    }

    public function text(): string
    {
        $o = "Apache / PHP 資安日報 " . date('Y-m-d') . "\n\n";
        if ($this->items === []) {
            $o .= "過去 24 小時沒有新的 Apache / PHP 漏洞或相關新聞。系統運作正常。\n";
        }
        foreach ($this->sorted() as $i) {
            $sev = $i->severity ? " [{$i->severity}" . ($i->score !== null ? " {$i->score}" : '') . ']' : '';
            $o .= "- [{$i->source}]$sev {$i->title}\n  {$i->url}\n";
            if ($i->summary !== '') {
                $o .= '  ' . $i->summary . "\n";
            }
        }
        foreach ($this->errors as $e) {
            $o .= "\n(來源錯誤: $e)";
        }
        return $o;
    }

    public function html(): string
    {
        $e = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $colors = ['CRITICAL' => '#b91c1c', 'HIGH' => '#ea580c', 'MEDIUM' => '#ca8a04', 'LOW' => '#16a34a'];
        $o = '<div style="font-family:sans-serif;max-width:720px"><h2>Apache / PHP 資安日報 ' . date('Y-m-d') . '</h2>';
        if ($this->items === []) {
            $o .= '<p>過去 24 小時沒有新的 Apache / PHP 漏洞或相關新聞。系統運作正常。</p>';
        }
        foreach ($this->sorted() as $i) {
            $badge = '';
            if ($i->severity) {
                $c = $colors[$i->severity] ?? '#6b7280';
                $badge = '<span style="background:' . $c . ';color:#fff;padding:1px 6px;border-radius:3px;font-size:12px">'
                    . $e($i->severity . ($i->score !== null ? ' ' . $i->score : '')) . '</span> ';
            }
            $url = preg_match('#^https?://#i', $i->url) ? $i->url : '#';
            $o .= '<div style="border-bottom:1px solid #ddd;padding:8px 0">' . $badge
                . '<small style="color:#666">[' . $e($i->source) . '] ' . $e($i->published->format('Y-m-d H:i')) . ' UTC</small><br>'
                . '<a href="' . $e($url) . '"><b>' . $e($i->title) . '</b></a>'
                . ($i->summary !== '' ? '<p style="margin:4px 0">' . $e($i->summary) . '</p>' : '') . '</div>';
        }
        foreach ($this->errors as $err) {
            $o .= '<p style="color:#b91c1c"><small>來源錯誤: ' . $e($err) . '</small></p>';
        }
        return $o . '</div>';
    }

    /** @return Item[] high severity first, then newest */
    private function sorted(): array
    {
        $items = $this->items;
        usort($items, fn(Item $a, Item $b) => [$b->score ?? -1, $b->published] <=> [$a->score ?? -1, $a->published]);
        return $items;
    }
}
