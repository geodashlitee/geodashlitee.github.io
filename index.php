<?php
// Whitelist of allowed endpoints (safe, controlled)
$allowed = [
    'example' => 'https://example.com',
    'api1'    => 'https://api.publicapis.org/entries'
];

// Choose which endpoint to load (?site=example)
$site = $_GET['site'] ?? '';

if (!isset($allowed[$site])) {
    http_response_code(400);
    echo "Invalid or unauthorized target.";
    exit;
}

$url = $allowed[$site];

// Fetch safely with a timeout + basic input protection
$context = stream_context_create([
    'http' => [
        'timeout' => 5,
        'user_agent' => 'SimpleProxy/1.0'
    ]
]);

$response = @file_get_contents($url, false, $context);

if ($response === false) {
    http_response_code(500);
    echo "Failed to fetch content.";
    exit;
}

// Return JSON response
header('Content-Type: application/json');
echo json_encode([
    'fetched_from' => $url,
    'data' => $response
]);
