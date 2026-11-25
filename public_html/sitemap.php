<?php
require __DIR__ . '/private/seo.php';
header('Content-Type: application/xml; charset=utf-8');
$U = seo_base();
$pages = ['', 'column/', 'column/custom-surfboard-order/', 'column/one-of-a-kind-surfboard/', 'column/unique-surfboards/', 'column/mid-length-surfboard/', 'column/how-to-choose-surfboard/', 'column/pu-vs-eps/', 'column/surfboard-tail-types/', 'column/surfboard-fin-setup/', 'column/surfboard-repair/', 'column/shirasuka-surf-guide/', 'column/shaper-vs-stock/', 'column/surfboard-care/', 'privacy.html'];
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
$dated = ['column/minamiboso-surfing/' => '2026-11-25', 'column/original-surfboard/' => '2026-11-26', 'column/chiba-south-surfing/' => '2026-11-27'];
$latest = '2026-10-30';
foreach ($dated as $p => $d) if (rx_today() >= $d) $latest = max($latest, $d);
foreach ($pages as $p) {
  $lm = ($p === '' || $p === 'column/') ? $latest : '2026-10-30';
  echo '  <url><loc>' . htmlspecialchars($U . $p, ENT_XML1) . '</loc><lastmod>' . $lm . '</lastmod></url>' . "\n";
}
foreach ($dated as $p => $d) {
  if (rx_today() < $d) continue;
  echo '  <url><loc>' . htmlspecialchars($U . $p, ENT_XML1) . '</loc><lastmod>' . $d . '</lastmod></url>' . "\n";
}
echo '</urlset>' . "\n";
