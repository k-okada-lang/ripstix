<?php
require __DIR__ . '/private/seo.php';
header('Content-Type: text/plain; charset=utf-8');
$U = seo_base();
echo "User-agent: *\nAllow: /\nDisallow: /private/\nDisallow: /api.php\n\nSitemap: {$U}sitemap.xml\n";
