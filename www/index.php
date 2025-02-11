<?php
// =============================
// Configuration
// =============================

// Change these settings to match your environment
define('JWT_SECRET', 'zlZKh+KR4TBN7EB52U21cA0Mf0uf+Xkx5Fqmkkj+Dvs='); // Use a strong secret in production

$dsn     = 'mysql:host=mysql;dbname=test_db;charset=utf8';
$db_user = 'user';
$db_pass = 'password';

try {
    $pdo = new PDO($dsn, $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    sendResponse(500, ['error' => 'Database connection failed', 'details' => $e->getMessage()]);
}

// =============================
// Rate Limiting
// =============================

/**
 * Checks the number of requests from the client’s IP in the current minute.
 * If >100 requests are detected, a 429 response is sent.
 */
function checkRateLimit() {
    $ip            = $_SERVER['REMOTE_ADDR'];
    $currentMinute = floor(time() / 60);
    // Use a file in the system temporary folder keyed by IP and minute.
    $filename = sys_get_temp_dir() . '/rate_' . md5($ip) . '_' . $currentMinute;
    
    if (file_exists($filename)) {
        $count = (int) file_get_contents($filename);
        if ($count >= 100) {
            sendResponse(429, ['error' => 'Too many requests']);
        }
        $count++;
        file_put_contents($filename, $count);
    } else {
        file_put_contents($filename, 1);
    }
}

// =============================
// Helper: Send JSON Response
// =============================

/**
 * Sends a JSON response and stops execution.
 *
 * @param int   $status HTTP status code.
 * @param array $data   Data to encode as JSON.
 */
function sendResponse($status, $data) {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// =============================
// JWT Functions
// =============================

/**
 * Generates a JWT using HS256.
 *
 * @param array $payload Data to include in the token.
 * @return string The JWT.
 */
function generateJWT($payload) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    
    // Add expiration if not set (here: 1 hour)
    if (!isset($payload['exp'])) {
        $payload['exp'] = time() + 3600;
    }
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($payload)));
    
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

/**
 * Verifies a JWT and returns its payload if valid.
 *
 * @param string $token The JWT.
 * @return mixed The payload array if valid; otherwise false.
 */
function verifyJWT($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }
    list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $parts;
    
    $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $base64UrlHeader)), true);
    if (!$header || $header['alg'] !== 'HS256') {
        return false;
    }
    
    $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $base64UrlPayload)), true);
    if (!$payload) {
        return false;
    }
    
    $signature = base64_decode(str_replace(['-', '_'], ['+', '/'], $base64UrlSignature));
    $expectedSignature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET, true);
    
    if (!hash_equals($expectedSignature, $signature)) {
        return false;
    }
    
    if (isset($payload['exp']) && time() >= $payload['exp']) {
        return false;
    }
    
    return $payload;
}

// =============================
// API Endpoints
// =============================

/**
 * Handles user registration.
 * Expects JSON body with "username", "email", and "password".
 */
function handleRegister() {
    global $pdo;
    
    $data = json_decode(file_get_contents('php://input'), true);
    if (!isset($data['username'], $data['email'], $data['password'])) {
        sendResponse(400, ['error' => 'Missing required fields: username, email, password']);
    }
    
    $username = trim($data['username']);
    $email    = trim($data['email']);
    $password = $data['password'];
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendResponse(400, ['error' => 'Invalid email address']);
    }
    
    // Check if a user with this email already exists.
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    if ($stmt->fetch()) {
        sendResponse(400, ['error' => 'User already exists']);
    }
    
    // Hash the password before saving.
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);
    
    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
    $stmt->execute([
        'username' => $username,
        'email'    => $email,
        'password' => $passwordHash
    ]);
    
    sendResponse(201, ['message' => 'User registered successfully']);
}

/**
 * Handles user login.
 * Expects JSON body with "email" and "password".
 * Returns a JWT token if credentials are valid.
 */
function handleLogin() {
    global $pdo;
    
    $data = json_decode(file_get_contents('php://input'), true);
    if (!isset($data['email'], $data['password'])) {
        sendResponse(400, ['error' => 'Missing required fields: email, password']);
    }
    
    $email    = trim($data['email']);
    $password = $data['password'];
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user || !password_verify($password, $user['password'])) {
        sendResponse(401, ['error' => 'Invalid credentials']);
    }
    
    // Create a JWT payload. You can include any data you need.
    $payload = [
        'id'       => $user['id'],
        'username' => $user['username'],
        'email'    => $user['email']
    ];
    $token = generateJWT($payload);
    
    sendResponse(200, ['token' => $token]);
}

/**
 * Returns user details for the authenticated user.
 * Requires a valid JWT to be sent in the "Authorization: Bearer <token>" header.
 */
function handleGetUser() {
    global $pdo;
    
    // Retrieve headers (compatible with various PHP setups)
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
    } else {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) === 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
    }
    
    if (!isset($headers['Authorization'])) {
        sendResponse(401, ['error' => 'Authorization header not found']);
    }
    
    // Expecting header in the form: "Bearer token"
    if (!preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
        sendResponse(401, ['error' => 'Invalid Authorization header format']);
    }
    
    $token = $matches[1];
    $payload = verifyJWT($token);
    if (!$payload) {
        sendResponse(401, ['error' => 'Invalid or expired token']);
    }
    
    // Retrieve user details from the database.
    $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = :id");
    $stmt->execute(['id' => $payload['id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        sendResponse(404, ['error' => 'User not found']);
    }
    
    sendResponse(200, ['user' => $user]);
}

// =============================
// Main Router
// =============================

// Check rate limit first
checkRateLimit();

// Determine the request path and method.
$requestMethod = $_SERVER['REQUEST_METHOD'];
$requestUri    = $_SERVER['REQUEST_URI'];
$parsedUrl     = parse_url($requestUri);
$path          = $parsedUrl['path'];

// Basic routing – in a larger application you might use a more robust router.
switch ($path) {
    case '/register':
        if ($requestMethod !== 'POST') {
            sendResponse(405, ['error' => 'Method not allowed']);
        }
        handleRegister();
        break;
        
    case '/login':
        if ($requestMethod !== 'POST') {
            sendResponse(405, ['error' => 'Method not allowed']);
        }
        handleLogin();
        break;
        
    case '/user':
        if ($requestMethod !== 'GET') {
            sendResponse(405, ['error' => 'Method not allowed']);
        }
        handleGetUser();
        break;
        
    default:
        sendResponse(404, ['error' => 'Endpoint not found']);
        break;
}
?>
