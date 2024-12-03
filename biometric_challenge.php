<?php
// biometric_challenge.php
session_start();
require_once 'includes/database.php';

header('Content-Type: application/json');

try {
    // Verify user is registered for biometric auth
    $email = $_SESSION['email'] ?? null; // Assume email is set during registration
    if (!$email) {
        throw new Exception('User not found');
    }

    // Fetch user's registered credentials
    $stmt = $conn->prepare("SELECT biometric_credential_id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (!$user || !$user['biometric_credential_id']) {
        throw new Exception('No biometric credentials registered');
    }

    // Generate a random challenge
    $challenge = bin2hex(random_bytes(32));
    $_SESSION['biometric_challenge'] = $challenge;

    // Prepare response
    $response = [
        'challenge' => base64_encode($challenge),
        'allowCredentials' => [
            [
                'type' => 'public-key',
                'id' => base64_encode($user['biometric_credential_id'])
            ]
        ]
    ];

    echo json_encode($response);
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}