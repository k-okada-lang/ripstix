<?php
require __DIR__ . '/private/seo.php';
header('Content-Type: application/xml; charset=utf-8');
$U = seo_base();
$pages = ['', 'column/', 'column/custom-surfboard-order/', 'column/one-of-a-kind-surfboard/', 'column/unique-surfboards/', 'column/mid-length-surfboard/', 'column/how-to-choose-surfboard/', 'column/pu-vs-eps/', 'column/surfboard-tail-types/', 'column/surfboard-fin-setup/', 'column/surfboard-repair/', 'column/shirasuka-surf-guide/', 'column/shaper-vs-stock/', 'column/surfboard-care/', 'privacy.html'];
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
foreach ($pages as $p) {
  echo '  <url><loc>' . htmlspecialchars($U . $p, ENT_XML1) . '</loc><lastmod>2026-10-30</lastmod></url>' . "\n";
}
echo '</urlset>' . "\n";
