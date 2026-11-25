# Apache / PHP 資安新聞每日 Email 提醒

用 PHP 8 撰寫（零第三方套件），每天透過 GitHub Actions 自動檢查並寄信：

- **NVD CVE API 2.0**：過去 26 小時內新公布、影響 Apache HTTP Server / PHP 的 CVE（含 CVSS 分數與嚴重度）
- **新聞 RSS**：php.net、The Hacker News、BleepingComputer、SecurityWeek（後三者以 apache/php 等關鍵字過濾）
- 沒有新項目也會寄「系統運作正常」通知（設 `SEND_EMPTY=0` 可改為沒新項目就不寄）
- 高風險（CRITICAL/HIGH）排在最前面，主旨會標示數量

## 設定（GitHub → Settings → Secrets and variables → Actions）

| Secret | 說明 |
|---|---|
| `SMTP_HOST` / `SMTP_PORT` | 例：`smtp.gmail.com` / `587`（587=STARTTLS、465=SSL） |
| `SMTP_USER` / `SMTP_PASS` | Gmail 請用「應用程式密碼」，不是登入密碼 |
| `MAIL_FROM` | 寄件者（可省略，預設 SMTP_USER） |
| `MAIL_TO` | 收件者，多人以逗號分隔 |
| `NVD_API_KEY` | 選填，免費申請，可避免被限流 |

排程在 `.github/workflows/daily.yml`，預設每天台灣時間 08:00；也可在 Actions 頁面手動 *Run workflow*。

## 本機執行

```bash
php bin/check.php --dry-run          # 只印出報告，不寄信
SMTP_USER=you@gmail.com SMTP_PASS=xxxx MAIL_TO=you@gmail.com php bin/check.php
php -d zend.assertions=1 -d assert.exception=1 tests/run.php
```

環境變數 `LOOKBACK_HOURS`（預設 26）可調整回溯時間。

## 擴充

新增來源：實作 `SecAlert\Source\Source`，加進 `bin/check.php` 的 `$sources`；或加一行 `FeedSource` 即可訂閱其他 RSS/Atom。
