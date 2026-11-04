<?php
/**
 * RIPSTIX 会員・注文・顧客管理 API（エックスサーバー用 / PHP 8 + SQLite）
 *
 * - データは private/ripstix.sqlite に保存されます（private フォルダは .htaccess で外部から読めません）。
 * - パスワードは password_hash() で保存し、元のパスワードは残しません。
 * - 設定は private/config.php で変更します。
 */
declare(strict_types=1);

require __DIR__ . '/private/config.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Referrer-Policy: same-origin');

const MAX_BODY = 300000;          // 1回のリクエストの上限（バイト）
const MAX_DOC = 262144;           // 1件のデータの上限（256KB）
const LOCK_FAILS = 5;             // この回数まちがえるとロック
const LOCK_SECONDS = 300;         // ロック時間（5分）
const RESET_TTL = 900;            // 確認コードの有効期限（15分）
const RESET_TRIES = 5;            // 確認コードの入力ミス上限
const RESET_COOLDOWN = 30;        // 再送できるまでの秒数
const REMEMBER_DAYS = 30;

/* ---------------------------------------------------------------- 共通 */
function out(array $a, int $http = 200): void { http_response_code($http); echo json_encode($a, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit; }
function fail(string $code, int $http = 400, array $extra = []): void { out(['error' => $code] + $extra, $http); }
function authfail(string $code, int $http = 400): void { out(['error' => 'auth', 'auth' => $code], $http); }
function now(): int { return time(); }
function ip(): string { return substr((string)($_SERVER['REMOTE_ADDR'] ?? '0'), 0, 64); }
function is_https(): bool {
  return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
}

function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;
  $file = __DIR__ . '/private/ripstix.sqlite';
  $pdo = new PDO('sqlite:' . $file, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
  $pdo->exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
  $pdo->exec('CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      hash TEXT NOT NULL,
      created INTEGER NOT NULL,
      updated INTEGER NOT NULL,
      fails INTEGER NOT NULL DEFAULT 0,
      lock_until INTEGER NOT NULL DEFAULT 0,
      reset_hash TEXT, reset_exp INTEGER NOT NULL DEFAULT 0, reset_tries INTEGER NOT NULL DEFAULT 0, reset_sent INTEGER NOT NULL DEFAULT 0)');
  try { $pdo->exec('ALTER TABLE accounts ADD COLUMN verified INTEGER NOT NULL DEFAULT 0'); } catch (PDOException $e) { /* 追加済み */ }
  $pdo->exec('CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, parent TEXT NOT NULL, data TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL)');
  $pdo->exec('CREATE INDEX IF NOT EXISTS docs_parent ON docs(parent)');
  $pdo->exec('CREATE TABLE IF NOT EXISTS tokens (selector TEXT PRIMARY KEY, vhash TEXT NOT NULL, uid INTEGER NOT NULL, exp INTEGER NOT NULL)');
  $pdo->exec('CREATE TABLE IF NOT EXISTS hits (k TEXT NOT NULL, t INTEGER NOT NULL)');
  $pdo->exec('CREATE INDEX IF NOT EXISTS hits_k ON hits(k, t)');
  @chmod($file, 0600);
  return $pdo;
}

/* 同じIPからの連続アクセスを制限（総当たり対策） */
function rate(string $what, int $max, int $window): void {
  $k = $what . ':' . ip(); $t = now();
  $d = db();
  if (random_int(1, 50) === 1) $d->prepare('DELETE FROM hits WHERE t < ?')->execute([$t - 86400]);
  $c = $d->prepare('SELECT COUNT(*) FROM hits WHERE k = ? AND t > ?'); $c->execute([$k, $t - $window]);
  if ((int)$c->fetchColumn() >= $max) authfail('rate', 429);
  $d->prepare('INSERT INTO hits (k, t) VALUES (?, ?)')->execute([$k, $t]);
}

function norm_email(string $e): string {
  $e = class_exists('Normalizer') ? (Normalizer::normalize($e, Normalizer::FORM_KC) ?: $e) : mb_convert_kana($e, 'as', 'UTF-8');
  return mb_strtolower(trim($e));
}
function email_ok(string $e): bool { return strlen($e) <= 120 && (bool)filter_var($e, FILTER_VALIDATE_EMAIL); }
function pw_problem(string $p): string {
  $n = mb_strlen($p);
  if ($n < 8) return 'short'; if ($n > 64) return 'long';
  if (!preg_match('/[A-Za-z]/', $p) || !preg_match('/\d/', $p)) return 'mix';
  return '';
}
function uid_of(int $id): string { return 'u' . $id; }
function admin_listed(?array $acc): bool {
  if (!$acc) return false;
  foreach (ADMIN_EMAILS as $a) if (norm_email($a) === $acc['email']) return true;
  return false;
}
/* 管理者になれるのは、ADMIN_EMAILS のアドレスで登録し、そのメールに届いた確認コードで「本人のアドレス」と確認できた人だけ */
function is_admin(?array $acc): bool { return admin_listed($acc) && (int)($acc['verified'] ?? 0) === 1; }
function pub(array $acc): array { return ['uid' => uid_of((int)$acc['id']), 'email' => $acc['email'], 'admin' => is_admin($acc), 'admin_pending' => admin_listed($acc) && !is_admin($acc)]; }
function send_code(array $acc, string $why): void {
  $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  db()->prepare('UPDATE accounts SET reset_hash = ?, reset_exp = ?, reset_tries = 0, reset_sent = ? WHERE id = ?')
    ->execute([hash_hmac('sha256', $code . ':' . $acc['id'], secret_key()), now() + RESET_TTL, now(), $acc['id']]);
  if ($why === 'verify') send_mail($acc['email'], '【RIPSTIX】管理者アドレスの確認コード',
    "RIPSTIX の管理画面を使うための確認コードです。\n\n    $code\n\nマイページの「管理者の確認」に入力してください。このコードは15分間有効です。\nお心当たりのない場合は、このメールを破棄してください。\n\nRIPSTIX / SPLASH\n");
  else send_mail($acc['email'], '【RIPSTIX】パスワード再設定の確認コード',
    "RIPSTIX をご利用いただきありがとうございます。\nパスワード再設定の確認コードは次のとおりです。\n\n    $code\n\nこのコードは15分間有効です。\nお心当たりのない場合は、このメールを破棄してください。パスワードは変更されません。\n\nRIPSTIX / SPLASH\n");
}
function check_code(array $acc, string $code): void {
  if (!$acc['reset_hash']) authfail('code');
  if ((int)$acc['reset_exp'] < now()) authfail('expired');
  if ((int)$acc['reset_tries'] >= RESET_TRIES) authfail('tries');
  if (!hash_equals($acc['reset_hash'], hash_hmac('sha256', $code . ':' . $acc['id'], secret_key()))) {
    db()->prepare('UPDATE accounts SET reset_tries = reset_tries + 1 WHERE id = ?')->execute([$acc['id']]);
    authfail('code');
  }
}

/* 確認コード用の秘密鍵：config.php の SECRET が空なら、初回に private/secret.key を自動で作って使います */
function secret_key(): string {
  if (defined('SECRET') && strlen((string)SECRET) >= 32) return (string)SECRET;
  $f = __DIR__ . '/private/secret.key';
  $k = is_file($f) ? trim((string)@file_get_contents($f)) : '';
  if (strlen($k) < 32) { $k = bin2hex(random_bytes(32)); @file_put_contents($f, $k, LOCK_EX); @chmod($f, 0600); }
  return $k;
}

/* ---------------------------------------------------------------- メール */
function mail_from(): string {
  $f = MAIL_FROM;
  if (!$f || str_contains($f, 'your-domain')) { $h = preg_replace('/[^a-z0-9.\-]/i', '', (string)($_SERVER['HTTP_HOST'] ?? 'localhost')); $f = 'no-reply@' . preg_replace('/^www\./', '', $h); }
  return $f;
}
function send_mail(string $to, string $subject, string $body): bool {
  if (!email_ok($to)) return false;
  $from = mail_from(); $subject = preg_replace('/[\r\n\t]+/', ' ', $subject);
  if (MAIL_DEBUG_LOG) @file_put_contents(__DIR__ . '/private/mail.log', date('c') . "\nTo: $to\nSubject: $subject\n\n$body\n-----\n", FILE_APPEND | LOCK_EX);
  if (!MAIL_ENABLED) return true;
  mb_language('uni'); mb_internal_encoding('UTF-8');
  $headers = 'From: ' . mb_encode_mimeheader(MAIL_FROM_NAME, 'UTF-8') . ' <' . $from . '>' . "\r\n" . 'Reply-To: ' . (SHOP_NOTIFY_EMAIL ?: $from);
  return @mb_send_mail($to, $subject, $body, $headers, '-f' . $from);
}
function site_url(): string {
  if (SITE_URL && !str_contains(SITE_URL, 'your-domain')) return SITE_URL;
  $h = preg_replace('/[^a-z0-9.:\-]/i', '', (string)($_SERVER['HTTP_HOST'] ?? ''));
  $dir = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
  return (is_https() ? 'https://' : 'http://') . $h . $dir . '/';
}

/* ---------------------------------------------------------------- セッション */
session_name('RSXSESS');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_start();

function current_account(): ?array {
  static $cache = false;
  if ($cache !== false) return $cache;
  $cache = null;
  $uid = $_SESSION['uid'] ?? null;
  if (!$uid && !empty($_COOKIE['RSXREM'])) {                 // 「ログインしたままにする」
    $parts = explode(':', (string)$_COOKIE['RSXREM'], 2);
    if (count($parts) === 2 && ctype_xdigit($parts[0]) && ctype_xdigit($parts[1])) {
      $s = db()->prepare('SELECT * FROM tokens WHERE selector = ?'); $s->execute([$parts[0]]); $t = $s->fetch();
      if ($t && $t['exp'] > now() && hash_equals($t['vhash'], hash('sha256', $parts[1]))) {
        session_regenerate_id(true); $_SESSION['uid'] = (int)$t['uid']; $uid = (int)$t['uid'];
      } else { forget_cookie(); }
    }
  }
  if ($uid) {
    $s = db()->prepare('SELECT * FROM accounts WHERE id = ?'); $s->execute([(int)$uid]); $a = $s->fetch();
    if ($a && isset($_SESSION['pwv']) && !hash_equals((string)$_SESSION['pwv'], pwv($a))) { $a = false; }   // パスワードが変わったら、ほかの端末は自動でログアウト
    if ($a) { $_SESSION['pwv'] = pwv($a); $cache = $a; } else { unset($_SESSION['uid'], $_SESSION['pwv']); }
  }
  return $cache;
}
function pwv(array $acc): string { return substr(hash('sha256', 'pwv:' . $acc['hash']), 0, 32); }
function remember(int $uid): void {
  $sel = bin2hex(random_bytes(9)); $val = bin2hex(random_bytes(24)); $exp = now() + REMEMBER_DAYS * 86400;
  db()->prepare('INSERT INTO tokens (selector, vhash, uid, exp) VALUES (?, ?, ?, ?)')->execute([$sel, hash('sha256', $val), $uid, $exp]);
  setcookie('RSXREM', $sel . ':' . $val, ['expires' => $exp, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
}
function forget_cookie(): void {
  if (!empty($_COOKIE['RSXREM'])) { $sel = explode(':', (string)$_COOKIE['RSXREM'])[0]; db()->prepare('DELETE FROM tokens WHERE selector = ?')->execute([$sel]); }
  setcookie('RSXREM', '', ['expires' => 1, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
}
function sign_in(array $acc, bool $rem): void {
  session_regenerate_id(true); $_SESSION['uid'] = (int)$acc['id']; $_SESSION['pwv'] = pwv($acc);
  if ($rem) remember((int)$acc['id']);
}
function csrf(): string { if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24)); return $_SESSION['csrf']; }

/* ---------------------------------------------------------------- データの読み書きルール
   members/<uid>/...   本人と管理者だけ。注文（orders）は本人は「新規作成」のみ、状況の変更は管理者だけ。
   crm/...             管理者だけ（店頭のお客さま・スタッフメモ）。
   それ以外のパスは使えません。 */
function segs(string $p): array {
  if ($p === '' || strlen($p) > 1000) fail('invalid_argument');
  $s = explode('/', $p);
  if (count($s) > 16) fail('invalid_argument');
  foreach ($s as $x) if (!preg_match('/^[A-Za-z0-9_\-.~:@+]{1,200}$/', $x) || $x === '.' || $x === '..') fail('invalid_argument');
  return $s;
}
function can(array $s, ?array $acc, string $op, bool $exists = false): bool {
  if (!$acc) return false;
  $admin = is_admin($acc); $me = uid_of((int)$acc['id']);
  if ($s[0] === 'members') {
    if (count($s) === 1) return $admin && $op === 'list';                 // 会員一覧は管理者だけ
    if ($s[1] === $me) {
      if (isset($s[2]) && $s[2] === 'orders' && count($s) >= 4 && in_array($op, ['update', 'delete', 'set'], true)) {
        return $admin || ($op === 'set' && !$exists);                       // 注文: 本人は新規作成のみ
      }
      return true;
    }
    return $admin;
  }
  if ($s[0] === 'crm') return $admin;
  return false;
}
function body_obj($v): array {
  if (!is_array($v) || (array_is_list($v) && $v !== [])) fail('invalid_argument');
  $j = json_encode($v, JSON_UNESCAPED_UNICODE);
  if ($j === false || strlen($j) > MAX_DOC) fail('invalid_argument');
  return $v;
}
function merge(array $a, array $b): array {
  foreach ($b as $k => $v) {
    if (is_array($v) && !array_is_list($v) && isset($a[$k]) && is_array($a[$k]) && !array_is_list($a[$k])) $a[$k] = merge($a[$k], $v);
    else $a[$k] = $v;
  }
  return $a;
}
function doc_read(string $path): ?array {
  $s = db()->prepare('SELECT data FROM docs WHERE path = ?'); $s->execute([$path]); $r = $s->fetchColumn();
  return $r === false ? null : json_decode((string)$r, true);
}
function doc_write(string $path, array $s, array $data, bool $isNew): void {
  $t = now(); $parent = implode('/', array_slice($s, 0, -1)); $j = json_encode($data, JSON_UNESCAPED_UNICODE);
  if ($isNew) db()->prepare('INSERT INTO docs (path, parent, data, created, updated) VALUES (?, ?, ?, ?, ?)')->execute([$path, $parent, $j, $t, $t]);
  else db()->prepare('UPDATE docs SET data = ?, updated = ? WHERE path = ?')->execute([$j, $t, $path]);
}
/* 新しい注文が入ったら、お店とお客さまにメールでお知らせ */
function notify_order(array $acc, array $s, array $o): void {
  $prof = doc_read('members/' . $s[1]) ?? [];
  $name = is_string($prof['name'] ?? null) ? $prof['name'] : '';
  $no = is_string($o['no'] ?? null) ? $o['no'] : '';
  $spec = is_string($o['text'] ?? null) ? mb_substr($o['text'], 0, 3000) : '';
  $cm = is_string($o['comment'] ?? null) ? mb_substr($o['comment'], 0, 1000) : '';
  $when = is_string($o['when'] ?? null) ? $o['when'] : ''; $how = is_string($o['contact'] ?? null) ? $o['contact'] : '';
  if (SHOP_NOTIFY_EMAIL) send_mail(SHOP_NOTIFY_EMAIL, '【RIPSTIX】新しいオーダーのお申し込み ' . $no,
    "新しいオーダーのお申し込みがありました。\n\n注文番号：$no\nお名前：$name 様\nメール：{$acc['email']}\n電話：" . ($prof['phone'] ?? '') .
    "\nご希望の時期：$when\nご希望の連絡方法：$how\nご要望：$cm\n\n$spec\n\n管理画面：" . site_url());
  send_mail($acc['email'], '【RIPSTIX】オーダーのお申し込みを受け付けました（' . $no . '）',
    "$name 様\n\nRIPSTIX をご利用いただきありがとうございます。\n以下の内容でお申し込みを受け付けました。内容を確認のうえ、ご希望の方法でお店からご連絡いたします。\n\n注文番号：$no\n\n$spec\n\n進み具合はマイページでご確認いただけます。\n" . site_url() .
    "\n\nRIPSTIX / SPLASH（株式会社LTR）\n〒299-2711 千葉県南房総市和田町白渚586-2\nTEL 0470-47-4334\n");
}

/* ---------------------------------------------------------------- リクエスト */
$a = (string)($_GET['a'] ?? '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$in = [];
if ($method === 'POST') {
  $raw = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
  if ($raw === false || strlen($raw) > MAX_BODY) fail('invalid_argument', 413);
  $in = json_decode($raw ?: '{}', true);
  if (!is_array($in)) fail('invalid_argument');
  /* 別サイトからの送信を防ぐ（CSRF対策） */
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST)) fail('forbidden', 403);
  if (!hash_equals(csrf(), (string)($_SERVER['HTTP_X_CSRF'] ?? ''))) fail('csrf', 403, ['csrf' => csrf()]);
} elseif (!in_array($a, ['ping', 'me'], true)) {
  fail('method', 405);
}
function str_in(array $in, string $k, int $max = 200): string { $v = $in[$k] ?? ''; return is_string($v) ? mb_substr($v, 0, $max) : ''; }

try {
  switch ($a) {
    case 'ping':
      out(['ok' => true]);

    case 'me':
      $acc = current_account();
      out(['user' => $acc ? pub($acc) : null, 'csrf' => csrf()]);

    case 'signup': {
      rate('signup', 10, 3600);
      $email = norm_email(str_in($in, 'email', 200)); $pw = str_in($in, 'password', 100);
      if (!email_ok($email)) authfail('email');
      if ($p = pw_problem($pw)) authfail('pw_' . $p);
      $t = now();
      try {
        db()->prepare('INSERT INTO accounts (email, hash, created, updated) VALUES (?, ?, ?, ?)')->execute([$email, password_hash($pw, PASSWORD_DEFAULT), $t, $t]);
      } catch (PDOException $e) { authfail('exists', 409); }
      $s = db()->prepare('SELECT * FROM accounts WHERE email = ?'); $s->execute([$email]); $acc = $s->fetch();
      if (admin_listed($acc)) send_code($acc, 'verify');
      sign_in($acc, true);
      out(['user' => pub($acc), 'csrf' => csrf()]);
    }

    case 'login': {
      rate('login', 30, 900);
      $email = norm_email(str_in($in, 'email', 200)); $pw = str_in($in, 'password', 100);
      $s = db()->prepare('SELECT * FROM accounts WHERE email = ?'); $s->execute([$email]); $acc = $s->fetch();
      if (!$acc) { password_verify($pw, '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG'); authfail('bad', 401); }
      if ((int)$acc['lock_until'] > now()) authfail('locked', 423);
      if (!password_verify($pw, $acc['hash'])) {
        $f = (int)$acc['fails'] + 1;
        if ($f >= LOCK_FAILS) { db()->prepare('UPDATE accounts SET fails = 0, lock_until = ? WHERE id = ?')->execute([now() + LOCK_SECONDS, $acc['id']]); authfail('locked', 423); }
        db()->prepare('UPDATE accounts SET fails = ? WHERE id = ?')->execute([$f, $acc['id']]);
        authfail('bad', 401);
      }
      db()->prepare('UPDATE accounts SET fails = 0, lock_until = 0 WHERE id = ?')->execute([$acc['id']]);
      if (password_needs_rehash($acc['hash'], PASSWORD_DEFAULT)) db()->prepare('UPDATE accounts SET hash = ? WHERE id = ?')->execute([password_hash($pw, PASSWORD_DEFAULT), $acc['id']]);
      sign_in($acc, !empty($in['remember']));
      out(['user' => pub($acc), 'csrf' => csrf()]);
    }

    case 'logout':
      forget_cookie(); $_SESSION = []; session_regenerate_id(true);
      out(['ok' => true, 'csrf' => csrf()]);

    case 'reset_request': {
      rate('reset', 8, 900);
      $email = norm_email(str_in($in, 'email', 200));
      if (!email_ok($email)) authfail('email');
      $s = db()->prepare('SELECT * FROM accounts WHERE email = ?'); $s->execute([$email]); $acc = $s->fetch();
      if ($acc && now() - (int)$acc['reset_sent'] >= RESET_COOLDOWN) send_code($acc, 'reset');
      out(['ok' => true]);                       // 登録の有無は返さない
    }

    case 'reset_confirm': {
      rate('reset_confirm', 30, 900);
      $email = norm_email(str_in($in, 'email', 200)); $code = preg_replace('/\D/', '', str_in($in, 'code', 20)); $pw = str_in($in, 'password', 100);
      if ($p = pw_problem($pw)) authfail('pw_' . $p);
      $s = db()->prepare('SELECT * FROM accounts WHERE email = ?'); $s->execute([$email]); $acc = $s->fetch();
      if (!$acc) authfail('code');
      check_code($acc, $code);
      db()->prepare('UPDATE accounts SET hash = ?, reset_hash = NULL, reset_exp = 0, reset_tries = 0, fails = 0, lock_until = 0, verified = 1, updated = ? WHERE id = ?')
        ->execute([password_hash($pw, PASSWORD_DEFAULT), now(), $acc['id']]);
      db()->prepare('DELETE FROM tokens WHERE uid = ?')->execute([$acc['id']]);       // ほかの端末のログインも解除
      out(['ok' => true]);
    }

    case 'verify_send': {                         // 管理者アドレスの確認コードを（再）送信
      $acc = current_account(); if (!$acc) authfail('login', 401);
      rate('verify', 6, 900);
      if (is_admin($acc) || !admin_listed($acc)) out(['ok' => true]);
      if (now() - (int)$acc['reset_sent'] < RESET_COOLDOWN) authfail('wait', 429);
      send_code($acc, 'verify'); out(['ok' => true]);
    }
    case 'verify_confirm': {
      $acc = current_account(); if (!$acc) authfail('login', 401);
      rate('verify_confirm', 20, 900);
      if (!admin_listed($acc)) authfail('code');
      check_code($acc, preg_replace('/\D/', '', str_in($in, 'code', 20)));
      db()->prepare('UPDATE accounts SET verified = 1, reset_hash = NULL, reset_exp = 0, reset_tries = 0 WHERE id = ?')->execute([$acc['id']]);
      $acc['verified'] = 1;
      out(['user' => pub($acc), 'csrf' => csrf()]);
    }

    case 'password_change': {
      $acc = current_account(); if (!$acc) authfail('login', 401);
      rate('pwchange', 10, 900);
      if (!password_verify(str_in($in, 'current', 100), $acc['hash'])) authfail('bad', 401);
      $pw = str_in($in, 'password', 100); if ($p = pw_problem($pw)) authfail('pw_' . $p);
      $nh = password_hash($pw, PASSWORD_DEFAULT);
      db()->prepare('UPDATE accounts SET hash = ?, updated = ? WHERE id = ?')->execute([$nh, now(), $acc['id']]);
      db()->prepare('DELETE FROM tokens WHERE uid = ?')->execute([$acc['id']]);
      session_regenerate_id(true); $_SESSION['pwv'] = pwv(['hash' => $nh]);      // この端末はログインしたまま、ほかの端末はログアウト
      out(['ok' => true, 'csrf' => csrf()]);
    }

    /* ---- データ（ボード・注文・プロフィール・顧客管理） ---- */
    case 'doc_get': case 'doc_set': case 'doc_update': case 'doc_delete': {
      $acc = current_account(); if (!$acc) authfail('login', 401);       // ログインが切れている
      $path = str_in($in, 'path', 1000); $s = segs($path);
      if (count($s) % 2) fail('invalid_argument');
      $cur = doc_read($path); $exists = $cur !== null;
      $op = ['doc_get' => 'get', 'doc_set' => 'set', 'doc_update' => 'update', 'doc_delete' => 'delete'][$a];
      if (!can($s, $acc, $op, $exists)) { if ($op === 'get') out(['exists' => false]); fail('invalid_argument', 403); }
      if ($op === 'get') out(['exists' => $exists, 'data' => $cur]);
      if ($op === 'delete') { db()->prepare('DELETE FROM docs WHERE path = ?')->execute([$path]); out(['ok' => true]); }
      $data = body_obj($in['data'] ?? null);
      if ($op === 'update') { if (!$exists) fail('invalid_argument', 404); $data = merge($cur, $data); body_obj($data); }
      $isOrder = $s[0] === 'members' && ($s[2] ?? '') === 'orders' && count($s) === 4;
      if (!is_admin($acc)) {
        if ($isOrder && !$exists) {                 // お客さまの新しい注文：状況・日時・番号はサーバーで決める
          $ms = now() * 1000;
          $data['status'] = '受付'; $data['createdAt'] = $ms; $data['updatedAt'] = $ms; $data['log'] = [['s' => '受付', 'at' => $ms]];
          $no = is_string($data['no'] ?? null) ? preg_replace('/[^A-Za-z0-9\-]/', '', $data['no']) : '';
          $data['no'] = $no !== '' ? substr($no, 0, 20) : 'RS-' . date('ymd') . '-' . strtoupper(bin2hex(random_bytes(2)));
        }
        if (count($s) === 2) $data['email'] = $acc['email'];   // プロフィールのメールは、ログインに使うアドレスに固定
      }
      doc_write($path, $s, $data, !$exists);
      if ($op === 'set' && !$exists && $isOrder) notify_order($acc, $s, $data);
      out(['ok' => true]);
    }

    case 'doc_list': {
      $acc = current_account(); if (!$acc) authfail('login', 401);
      $col = str_in($in, 'col', 1000); $s = segs($col);
      if (count($s) % 2 === 0) fail('invalid_argument');
      if (!can($s, $acc, 'list')) out(['docs' => []]);
      $q = db()->prepare('SELECT path, data FROM docs WHERE parent = ? ORDER BY path LIMIT 1000'); $q->execute([$col]);
      $docs = [];
      foreach ($q as $r) { $id = substr($r['path'], strlen($col) + 1); $docs[] = ['id' => $id, 'data' => json_decode($r['data'], true)]; }
      out(['docs' => $docs]);
    }

    default:
      fail('unknown', 404);
  }
} catch (Throwable $e) {
  if (MAIL_DEBUG_LOG) @file_put_contents(__DIR__ . '/private/error.log', date('c') . ' ' . $e->getMessage() . "\n", FILE_APPEND | LOCK_EX);
  fail('unavailable', 500);
}
