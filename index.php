<?php
// ---------------------------
// Simple Safe PHP Proxy
// ---------------------------

// 1. Allowed target domains (VERY important for security)
$allowed_domains = [
    "example.com",
    "api.example.com",
    "your-api-here.com"
];

// 2. Get URL from query parameter
if (!isset($_GET['url'])) {
    http_response_code(400);
    echo "Missing 'url' parameter.";
    exit;
}

$url = $_GET['url'];

// 3. Block dangerous protocols
if (preg_match('/^(file|php|data|glob|phar):/i', $url)) {
    http_response_code(400);
    echo "Blocked insecure protocol.";
    exit;
}

// 4. Parse domain
$parsed = parse_url($url);
$domain = $parsed['host'] ?? '';

if (!in_array($domain, $allowed_domains)) {
    http_response_code(403);
    echo "Domain is not allowed.";
    exit;
}

// 5. Initialize cURL
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

// 6. Perform the request
$response = curl_exec($ch);

// 7. Set response headers
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);

curl_close($ch);

http_response_code($http_code);
if ($content_type) {
    header("Content-Type: " . $content_type);
}

echo $response;
?>
