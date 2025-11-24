<?php
// proxy.php

// 1) Configure a whitelist to prevent abuse
$WHITELIST = [
  'example.com',
  'api.github.com',
  'httpbin.org'
];

// 2) Read and validate the URL
$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if ($url === '') {
  http_response_code(400);
  echo 'Missing ?url= parameter.';
  exit;
}

if (!filter_var($url, FILTER_VALIDATE_URL)) {
  http_response_code(400);
  echo 'Invalid URL.';
  exit;
}

// 3) Enforce HTTPS and whitelist domain
$parts = parse_url($url);
$host = $parts['host'] ?? '';
$scheme = $parts['scheme'] ?? '';

if ($scheme !== 'https') {
  http_response_code(400);
  echo 'Only HTTPS URLs are allowed.';
  exit;
}

$hostAllowed = in_array($host, $WHITELIST, true);
if (!$hostAllowed) {
  http_response_code(403);
  echo 'Domain not allowed.';
  exit;
}

// 4) Optional: limit path/query length
$path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
if (strlen($path) > 2000) {
  http_response_code(414);
  echo 'Request too long.';
  exit;
}

// 5) Fetch via cURL (GET only, no cookies forwarded)
$ch = curl_init();
curl_setopt_array($ch, [
  CURLOPT_URL            => $url,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_FOLLOWLOCATION => true,
  CURLOPT_MAXREDIRS      => 3,
  CURLOPT_CONNECTTIMEOUT => 5,
  CURLOPT_TIMEOUT        => 10,
  CURLOPT_SSL_VERIFYPEER => true,
  CURLOPT_SSL_VERIFYHOST => 2,
  // Safe default headers; do NOT forward user cookies
  CURLOPT_HTTPHEADER     => [
    'User-Agent: Safe-Proxy/1.0',
    'Accept: */*'
  ],
]);

$responseBody = curl_exec($ch);
$errno = curl_errno($ch);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
$httpCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
curl_close($ch);

if ($errno) {
  http_response_code(502);
  echo 'Upstream fetch error.';
  exit;
}

// 6) Pass through content type, but never set cookies
if ($contentType) {
  header('Content-Type: ' . $contentType);
}
http_response_code($httpCode);

// 7) Stream body (you may add size limits)
echo $responseBody;
