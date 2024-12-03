<?php
// biometric_verify.php
session_start();
require_once 'includes/database.php';

header('Content-Type: application/json');

try {
    // Get raw POST data
    $postData = json_decode(file_get_contents('php://input'), true);

    // Validate challenge and credentials
    $email = $_SESSION['email'] ?? null;
    if (!$email) {
        throw new Exception('User not found');
    }

    // Fetch user's registered credentials
    $stmt = $conn->prepare("SELECT biometric_credential_id, biometric_public_key FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (!$user || !$user['biometric_credential_id']) {
        throw new Exception('No biometric credentials registered');
    }

    // Verify authentication response
    // Note: In a real-world scenario, you'd use a proper WebAuthn library for verification
    // This is a simplified example and should be enhanced with proper cryptographic checks
    $verified = verifyAuthenticationResponse(
        $postData, 
        $user['biometric_credential_id'], 
        $user['biometric_public_key']
    );

    if ($verified) {
        // Start user session
        $_SESSION['user'] = $email;
        $_SESSION['logged_in'] = true;
        
        echo json_encode(['success' => true]);
    } else {
        throw new Exception('Authentication failed');
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

// Simplified verification function (replace with a robust WebAuthn library in production)
function verifyAuthenticationResponse($authData, $storedCredentialId, $storedPublicKey) {
    try {
        // 1. Decode base64 encoded data
        $rawId = base64_decode($authData['rawId']);
        $authenticatorData = base64_decode($authData['response']['authenticatorData']);
        $clientDataJSON = base64_decode($authData['response']['clientDataJSON']);
        $signature = base64_decode($authData['response']['signature']);
        
        // 2. Verify Credential ID matches
        if (base64_encode($rawId) !== base64_encode($storedCredentialId)) {
            error_log("Credential ID mismatch");
            return false;
        }

        // 3. Validate Client Data JSON
        $clientData = json_decode($clientDataJSON, true);
        if (!$clientData) {
            error_log("Invalid client data JSON");
            return false;
        }

        // 4. Check challenge (should match the one stored in session)
        $expectedChallenge = base64_encode($_SESSION['biometric_challenge']);
        if ($clientData['challenge'] !== $expectedChallenge) {
            error_log("Challenge mismatch");
            return false;
        }

        // 5. Verify origin matches current site
        $expectedOrigin = 'https://' . $_SERVER['HTTP_HOST'];
        if ($clientData['origin'] !== $expectedOrigin) {
            error_log("Origin mismatch: expected {$expectedOrigin}, got {$clientData['origin']}");
            return false;
        }

        // 6. Verify authentication type
        if ($clientData['type'] !== 'webauthn.get') {
            error_log("Invalid authentication type");
            return false;
        }

        // 7. Parse Authenticator Data
        $rpIdHash = substr($authenticatorData, 0, 32);
        $flags = ord(substr($authenticatorData, 32, 1));
        $signCount = unpack("N", substr($authenticatorData, 33, 4))[1];

        // Check user presence and user verification flags
        $userPresent = ($flags & 0x01) !== 0;
        $userVerified = ($flags & 0x04) !== 0;

        if (!$userPresent || !$userVerified) {
            error_log("User presence or verification failed");
            return false;
        }

        // 8. Cryptographic Signature Verification
        // Note: This requires OpenSSL and proper public key handling
        // You would typically use a WebAuthn library for this
        $verificationData = $authenticatorData . hash('sha256', $clientDataJSON, true);
        
        // Reconstruct public key (simplified - use proper key parsing in production)
        $publicKeyPem = formatPublicKey($storedPublicKey);
        
        $signatureVerification = openssl_verify(
            $verificationData, 
            $signature, 
            $publicKeyPem, 
            OPENSSL_ALGO_SHA256
        );

        if ($signatureVerification !== 1) {
            error_log("Signature verification failed");
            return false;
        }

        // 9. Additional security checks can be added here
        // e.g., check against replay attacks, validate sign count, etc.

        // If all checks pass
        return true;

    } catch (Exception $e) {
        error_log("WebAuthn verification error: " . $e->getMessage());
        return false;
    }
}

// Helper function to format public key (simplified)
function formatPublicKey($storedPublicKey) {
    // In a real-world scenario, you'd use a proper ASN.1 / DER encoding parser
    // This is a simplified example and should be replaced with robust key parsing
    $pemHeader = "-----BEGIN PUBLIC KEY-----\n";
    $pemFooter = "\n-----END PUBLIC KEY-----";
    
    // Base64 encode the public key if it's not already
    $formattedKey = base64_encode(base64_decode($storedPublicKey));
    
    return $pemHeader . chunk_split($formattedKey, 64, "\n") . $pemFooter;
}