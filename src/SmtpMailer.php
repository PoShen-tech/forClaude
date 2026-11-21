<?php
declare(strict_types=1);

namespace SecAlert;

/** Minimal dependency-free SMTP client (implicit TLS on 465 or STARTTLS on 587). */
final class SmtpMailer
{
    /** @var resource|null */
    private $fp = null;

    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $user,
        private readonly string $pass,
        private readonly string $from,
    ) {
    }

    /** @param string[] $to */
    public function send(array $to, string $subject, string $html, string $text): void
    {
        $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $scheme = $this->port === 465 ? 'ssl' : 'tcp';
        $fp = @stream_socket_client("$scheme://{$this->host}:{$this->port}", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) {
            throw new \RuntimeException("SMTP connect failed: $errstr ($errno)");
        }
        stream_set_timeout($fp, 30);
        $this->fp = $fp;
        try {
            $this->expect(220);
            $this->cmd('EHLO secalert.local', 250);
            if ($scheme === 'tcp') {
                $this->cmd('STARTTLS', 220);
                if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new \RuntimeException('STARTTLS negotiation failed');
                }
                $this->cmd('EHLO secalert.local', 250);
            }
            if ($this->user !== '') {
                $this->cmd('AUTH LOGIN', 334);
                $this->cmd(base64_encode($this->user), 334);
                $this->cmd(base64_encode($this->pass), 235);
            }
            $this->cmd('MAIL FROM:<' . self::addr($this->from) . '>', 250);
            foreach ($to as $rcpt) {
                $this->cmd('RCPT TO:<' . self::addr($rcpt) . '>', [250, 251]);
            }
            $this->cmd('DATA', 354);
            $msg = $this->build($to, $subject, $html, $text);
            // dot-stuffing, then terminator
            $msg = preg_replace('/^\./m', '..', $msg);
            fwrite($fp, $msg . "\r\n.\r\n");
            $this->expect(250);
            $this->cmd('QUIT', 221);
        } finally {
            fclose($fp);
            $this->fp = null;
        }
    }

    /** @param string[] $to */
    private function build(array $to, string $subject, string $html, string $text): string
    {
        $b = 'b_' . bin2hex(random_bytes(8));
        $h = [
            'From: ' . $this->from,
            'To: ' . implode(', ', $to),
            'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=',
            'Date: ' . date('r'),
            'Message-ID: <' . bin2hex(random_bytes(10)) . '@secalert.local>',
            'MIME-Version: 1.0',
            "Content-Type: multipart/alternative; boundary=\"$b\"",
        ];
        $part = static fn(string $type, string $body): string =>
            "--$b\r\nContent-Type: $type; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($body));
        return implode("\r\n", $h) . "\r\n\r\n"
            . $part('text/plain', $text) . $part('text/html', $html) . "--$b--";
    }

    private static function addr(string $a): string
    {
        return preg_match('/<([^>]+)>/', $a, $m) ? $m[1] : trim($a);
    }

    /** @param int|int[] $codes */
    private function cmd(string $line, int|array $codes): string
    {
        fwrite($this->fp, $line . "\r\n");
        return $this->expect($codes);
    }

    /** @param int|int[] $codes */
    private function expect(int|array $codes): string
    {
        $codes = (array) $codes;
        $resp = '';
        while (($line = fgets($this->fp, 1024)) !== false) {
            $resp .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }
        if (!in_array((int) substr($resp, 0, 3), $codes, true)) {
            throw new \RuntimeException('SMTP error, expected ' . implode('/', $codes) . ', got: ' . trim($resp));
        }
        return $resp;
    }
}
