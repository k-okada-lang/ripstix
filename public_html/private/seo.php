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
