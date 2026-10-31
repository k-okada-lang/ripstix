<?php
/* ============================================================
   RIPSTIX サイト設定（アップロード前にここだけ書き換えてください）
   ============================================================ */

/* 管理画面（ADMIN・顧客管理）に入れるメールアドレス。
   ここに書いたアドレスで「会員登録」すると、そのアカウントが管理者になります。複数書けます。 */
const ADMIN_EMAILS = [
  'admin@your-domain.jp',
];

/* メールの送信元（エックスサーバーで作成した、このドメインのメールアドレス） */
const MAIL_FROM = 'info@your-domain.jp';
const MAIL_FROM_NAME = 'RIPSTIX / SPLASH';

/* 新しいオーダーのお知らせを受け取るメールアドレス */
const SHOP_NOTIFY_EMAIL = 'info@your-domain.jp';

/* サイトのURL（例：'https://ripstix.jp/'）。検索エンジン向けの正式なURL・サイトマップ・メール本文に使います。
   空欄なら表示中のドメインから自動で判定します。ドメインが決まったら書いておくのがおすすめです。 */
const SITE_URL = '';

/* メールを実際に送るか（通常は true のまま） */
const MAIL_ENABLED = true;

/* 動作確認用：送ったメールとエラーを private/ に記録します（公開中は false 推奨） */
const MAIL_DEBUG_LOG = false;

/* 確認コード用の秘密の文字列。空欄のままなら、初回アクセス時に private/secret.key へ自動で作られます（変更不要）。 */
const SECRET = '';
