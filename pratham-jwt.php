<?php
/*
Plugin Name: Pratham JWT Authentication
Plugin URI: http://example.com/the-plugin
Description: To Create Custom JWT Token
Version: 1.0
Author: Pratham
Author URI: http://example.com
License: GPL2?
*/

// Importing Libraries
require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;



// Secret key for signing and verifying tokens
define('JWT_SECRET', 'R0 t%x6>;e1e&F=|}GL-iL8rC,@sads0y=3TMvo<u@v:~2` $`8=*O5emU|');

// Function to generate a JWT token
function generate_jwt_token($user_id) {
    $issuedAt = time();
    $expirationTime = $issuedAt + 3600; // 1 hour expiration

    $payload = array(
        'iss' => 'http://localhost/hotel/',
        'aud' => 'your_client_application',
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'user_id' => $user_id,
    );

    $jwt = JWT::encode($payload, JWT_SECRET, 'HS256');
    return $jwt;
}

// Function to verify a JWT token
function verify_jwt_token($token) {
    try {
        $decoded = JWT::decode($token, JWT_SECRET, array('HS256'));
        return $decoded;
    } catch (Exception $e) {
        // Token is invalid
        return false;
    }
}


// Custom endpoint for user authentication and JWT token generation
function custom_user_auth_endpoint(WP_REST_Request $request) {
    // Retrieve username and password from the request parameters
    $username = $request->get_param('username');
    $email = $request->get_param('email');
    $password = $request->get_param('password');

    // Validate username and password (customize this based on your authentication system)
    $user = wp_authenticate($username, $password);

    if (is_wp_error($user)) {
        // Authentication failed
        return new WP_REST_Response(array('error' => 'Invalid credentials'), 401);
    }

    // Authentication successful, generate JWT token
    $user_id = $user->ID;
    $token = generate_jwt_token($user_id);

    // Return the token in the response
    return new WP_REST_Response(array('token' => $token), 200);
}

// Register the custom endpoint
function register_custom_endpoints() {
    register_rest_route('pratham-jwt/v1', '/auth/', array(
        'methods' => 'POST',
        'callback' => 'custom_user_auth_endpoint',
    ));
}
add_action('rest_api_init', 'register_custom_endpoints');


define('MY_PLUGIN_DIR', plugin_dir_path(__FILE__));


// echo __FILE__;



/*  Testing Code
// Example usage
$user_id = 2;
$token = generate_jwt_token($user_id);
$decoded_token = verify_jwt_token($token);

if ($decoded_token) {
    // Token is valid
    echo 'Token is valid. User ID: ' . $token;
} else {
    // Token is invalid
    echo 'Token is invalid.';
}

?>


*/