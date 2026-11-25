<?php
/* 検索エンジン向けの正式なURL（https://ドメイン/）を返します。
   private/config.php の SITE_URL に書けばそれを使い、空欄なら表示中のドメインから自動で作ります。 */
require_once __DIR__ . '/config.php';
function seo_base(): string {
  if (defined('SITE_URL') && SITE_URL !== '' && !str_contains(SITE_URL, 'your-domain')) return rtrim(SITE_URL, '/') . '/';
  $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
  $host = preg_replace('/[^a-z0-9.:\-]/i', '', (string)($_SERVER['HTTP_HOST'] ?? 'localhost'));
  $s = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? '/'));
  $p = strpos($s, '/column/');
  $root = $p !== false ? substr($s, 0, $p + 1) : rtrim(dirname($s), '/') . '/';
  return ($https ? 'https://' : 'http://') . $host . $root;
}
/* 予約公開：日本時間で公開日になるまで記事を出さない */
function rx_today(): string { return (new DateTimeImmutable('now', new DateTimeZone('Asia/Tokyo')))->format('Y-m-d'); }
function rx_live(string $d): bool { return rx_today() >= $d || (($_GET['rxpv'] ?? '') === 'k7Pq2w'); }
function rx_gate(string $d): void {
  if (rx_live($d)) return;
  http_response_code(404); header('X-Robots-Tag: noindex');
  echo '<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ページが見つかりません｜RIPSTIX</title><p style="font-family:sans-serif;padding:40px 16px">ページが見つかりません。<a href="/">トップへ戻る</a></p></html>';
  exit;
}
