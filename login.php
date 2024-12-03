<?php include 'includes/session.php'; ?>
<?php
  if(isset($_SESSION['user'])){
    header('location: cart_view.php');
  }
?>
<?php include 'includes/header.php'; ?>
<body class="bg-primary">

<div class="login-box">
  	<?php
      if(isset($_SESSION['error'])){
        echo "
          <div class='alert alert-danger text-center'>
            <p>".$_SESSION['error']."</p> 
          </div>
        ";
        unset($_SESSION['error']);
      }
      if(isset($_SESSION['success'])){
        echo "
          <div class='alert alert-success text-center'>
            <p>".$_SESSION['success']."</p> 
          </div>
        ";
        unset($_SESSION['success']);
      }
    ?>
  	<div class="login-box-body shadow-lg p-5 rounded-lg">
    	<p class="login-box-msg text-center text-white h3">Welcome Back! Please Sign In</p>

      <!-- Traditional Login Form -->
    	<form action="verify.php" method="POST" id="traditional-login">
      		<div class="form-group mb-4">
        		<input type="email" class="form-control form-control-lg" name="email" placeholder="Email" required>
        		<div class="input-group-append">
        			<span class="input-group-text"><i class="fa fa-envelope"></i></span>
        		</div>
      		</div>
          <div class="form-group mb-4">
            <input type="password" class="form-control form-control-lg" name="password" placeholder="Password" required>
            <div class="input-group-append">
              <span class="input-group-text"><i class="fa fa-lock"></i></span>
            </div>
          </div>
      		<div class="row">
    			<div class="col-12">
          			<button type="submit" class="btn btn-dark btn-lg btn-block" name="login"><i class="fa fa-sign-in"></i> Sign In</button>
        		</div>
      		</div>
    	</form>

      <!-- Biometric Authentication Section -->
      <div class="text-center my-3">
        <div class="separator">
          <span>OR</span>
        </div>
      </div>
      <div class="text-center">
        <button id="biometric-login" class="btn btn-primary btn-lg">
          <i class="fa fa-fingerprint"></i> Login with Biometrics
        </button>
      </div>

      <!-- Links section -->
      <div class="text-center mt-4">
        <a href="password_forgot.php" class="text-muted">Forgot your password?</a><br>
        <a href="signup.php" class="text-muted">Create a new account</a><br>
        <a href="index.php" class="text-muted"><i class="fa fa-home"></i> Back to Home</a>
      </div>
  	</div>
</div>

<?php include 'includes/scripts.php' ?>

<script>
// Biometric Authentication Logic
document.addEventListener('DOMContentLoaded', () => {
  const biometricLoginBtn = document.getElementById('biometric-login');

  // Check if WebAuthn is supported
  if (!window.PublicKeyCredential) {
    biometricLoginBtn.disabled = true;
    biometricLoginBtn.textContent = 'Biometrics Not Supported';
    return;
  }

  biometricLoginBtn.addEventListener('click', async () => {
    try {
      // Request authentication challenge from server
      const response = await fetch('biometric_challenge.php', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to get authentication challenge');
      }

      const challengeData = await response.json();

      // WebAuthn authentication options
      const authOptions = {
        challenge: base64ToBuffer(challengeData.challenge),
        rpId: window.location.hostname,
        userVerification: 'preferred',
        allowCredentials: challengeData.allowCredentials.map(credential => ({
          type: 'public-key',
          id: base64ToBuffer(credential.id)
        }))
      };

      // Attempt WebAuthn authentication
      const credential = await navigator.credentials.get({
        publicKey: authOptions
      });

      // Send authentication response to server
      const authResponse = await fetch('biometric_verify.php', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          id: credential.id,
          rawId: bufferToBase64(credential.rawId),
          type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment,
          response: {
            authenticatorData: bufferToBase64(credential.response.authenticatorData),
            clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
            signature: bufferToBase64(credential.response.signature),
            userHandle: bufferToBase64(credential.response.userHandle)
          }
        })
      });

      const verificationResult = await authResponse.json();

      if (verificationResult.success) {
        window.location.href = 'cart_view.php';
      } else {
        alert('Biometric authentication failed');
      }

    } catch (error) {
      console.error('Biometric authentication error:', error);
      alert('Biometric authentication failed');
    }
  });

  // Utility functions for base64 encoding/decoding
  function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }

  function bufferToBase64(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
  }
});
</script>

<!-- Add some custom CSS for the separator -->
<style>
.separator {
  display: flex;
  align-items: center;
  text-align: center;
  margin: 20px 0;
}

.separator::before,
.separator::after {
  content: '';
  flex: 1;
  border-bottom: 1px solid #ddd;
}

.separator span {
  padding: 0 10px;
  color: #888;
}
</style>