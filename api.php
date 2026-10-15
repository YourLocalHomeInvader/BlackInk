<?php
// Black Ink Network (BIN) - Secure API Controller
ob_start();

ini_set('display_errors', 1);
error_reporting(E_ALL);
ini_set('log_errors', 1);
ini_set('error_log', dirname(__DIR__) . '/secure_bin_storage/error.log');

get_current_time: // 2026

ini_set('upload_max_filesize', '150G');
ini_set('post_max_size', '150G');
ini_set('memory_limit', '2048M');

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { 
    http_response_code(200);
    exit;
}

function sendJsonResponse($data, $statusCode = 200) {
    if (ob_get_length()) ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($statusCode);
    echo json_encode($data);
    exit;
}

function getClientIP() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return filter_var(trim($ip), FILTER_VALIDATE_IP) ? trim($ip) : $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
}

$action = isset($_GET['action']) ? $_GET['action'] : '';

$secureDataDir = dirname(__DIR__) . '/secure_bin_storage/';
if (!file_exists($secureDataDir)) {
    @mkdir($secureDataDir, 0755, true);
}

$usersFile = $secureDataDir . 'users.json';
$bansFile = $secureDataDir . 'bans.json';
$messagesFile = $secureDataDir . 'messages.json';
$reportsFile = $secureDataDir . 'reports.json';
$lastReadFile = $secureDataDir . 'last_read.json';
$adminMetaFile = $secureDataDir . 'admin_meta.json';
$secureUploadsDir = $secureDataDir . 'uploads/';
if (!file_exists($secureUploadsDir)) {
    @mkdir($secureUploadsDir, 0755, true);
}

if ($action === 'ping') {
    $port = isset($_GET['port']) ? intval($_GET['port']) : 0;
    $isOnline = false;

    if ($port > 0) {
        $hosts = ['127.0.0.1', '74.141.6.74', 'localhost'];
        foreach ($hosts as $host) {
            $connection = @fsockopen($host, $port, $errno, $errstr, 0.8);
            if (is_resource($connection)) {
                fclose($connection);
                $isOnline = true;
                break;
            }
        }

        if (!$isOnline && in_array($port, [80, 443, 7000, 30120])) {
            $testUrl = ($port === 443) ? "https://74.141.6.74" : "http://74.141.6.74:{$port}";
            $ch = curl_init($testUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode > 0) {
                $isOnline = true;
            }
        }
    }
    sendJsonResponse(['status' => 'success', 'online' => $isOnline]);
}

function loadUsersData($file) {
    if (!file_exists($file)) return [];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    if (!is_array($data)) return [];
    
    $normalized = [];
    foreach ($data as $uname => $info) {
        if (is_string($info)) {
            $normalized[$uname] = [
                'password' => $info, 
                'vault_password' => null,
                'ips' => [],
                'is_banned' => false
            ];
        } else if (is_array($info)) {
            $normalized[$uname] = [
                'password' => isset($info['password']) ? $info['password'] : '',
                'vault_password' => isset($info['vault_password']) ? $info['vault_password'] : null,
                'ips' => isset($info['ips']) && is_array($info['ips']) ? $info['ips'] : [],
                'is_banned' => isset($info['is_banned']) ? (bool)$info['is_banned'] : false
            ];
        }
    }
    return $normalized;
}

function loadBansData($file) {
    if (!file_exists($file)) return ['ips' => []];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    return is_array($data) ? $data : ['ips' => []];
}

function loadReportsData($file) {
    if (!file_exists($file)) return [];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

function loadLastReadData($file) {
    if (!file_exists($file)) return [];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

function loadAdminMetaData($file) {
    if (!file_exists($file)) return [];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

function isIpBanned($ip, $bansFile) {
    $bans = loadBansData($bansFile);
    return in_array($ip, $bans['ips'] ?? []);
}

function logUserIp(&$usersData, $username, $ip) {
    if (!isset($usersData[$username])) return;
    if (!isset($usersData[$username]['ips'])) {
        $usersData[$username]['ips'] = [];
    }
    if (!in_array($ip, $usersData[$username]['ips'])) {
        $usersData[$username]['ips'][] = $ip;
    }
}

if ($action === 'get_users') {
    $usersData = loadUsersData($usersFile);
    $sanitizedUsers = [];
    foreach ($usersData as $uname => $info) {
        $sanitizedUsers[$uname] = [
            'is_banned' => !empty($info['is_banned'])
        ];
    }
    sendJsonResponse(['status' => 'success', 'users' => $sanitizedUsers]);
}

if ($action === 'admin_get_users') {
    $requester = isset($_GET['requester']) ? trim($_GET['requester']) : '';
    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }
    $usersData = loadUsersData($usersFile);
    $bansData = loadBansData($bansFile);
    $sanitized = [];
    foreach ($usersData as $uname => $info) {
        $sanitized[$uname] = [
            'ips' => $info['ips'] ?? [],
            'is_banned' => $info['is_banned'] ?? false
        ];
    }
    sendJsonResponse([
        'status' => 'success', 
        'users_data' => $sanitized,
        'banned_ips' => $bansData['ips'] ?? []
    ]);
}

if ($action === 'admin_get_reports') {
    $requester = isset($_GET['requester']) ? trim($_GET['requester']) : '';
    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }
    $reports = loadReportsData($reportsFile);
    sendJsonResponse(['status' => 'success', 'reports' => $reports]);
}

if ($action === 'admin_get_dm_transcript') {
    $requester = isset($_GET['requester']) ? trim($_GET['requester']) : '';
    $userA = isset($_GET['user_a']) ? trim($_GET['user_a']) : '';
    $userB = isset($_GET['user_b']) ? trim($_GET['user_b']) : '';

    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }

    $msgs = file_exists($messagesFile) ? json_decode(file_get_contents($messagesFile), true) ?: [] : [];
    $transcript = [];

    foreach ($msgs as $m) {
        $sender = $m['sender'] ?? '';
        $recipient = $m['recipient'] ?? '';
        if (($sender === $userA && $recipient === $userB) || ($sender === $userB && $recipient === $userA)) {
            $transcript[] = $m;
        }
    }

    sendJsonResponse(['status' => 'success', 'transcript' => $transcript]);
}

if ($action === 'admin_mark_reports_read') {
    $input = json_decode(file_get_contents('php://input'), true);
    $requester = isset($input['requester']) ? trim($input['requester']) : '';
    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }
    $meta = loadAdminMetaData($adminMetaFile);
    $meta['reports_last_read'] = time();
    file_put_contents($adminMetaFile, json_encode($meta, JSON_PRETTY_PRINT));
    sendJsonResponse(['status' => 'success']);
}

if ($action === 'admin_delete_report') {
    $input = json_decode(file_get_contents('php://input'), true);
    $requester = isset($input['requester']) ? trim($input['requester']) : '';
    $reportIndex = isset($input['report_index']) ? intval($input['report_index']) : -1;

    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }

    $reports = loadReportsData($reportsFile);
    if ($reportIndex >= 0 && isset($reports[$reportIndex])) {
        array_splice($reports, $reportIndex, 1);
        file_put_contents($reportsFile, json_encode(array_values($reports), JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => 'Report deleted']);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Invalid report index'], 400);
}

if ($action === 'get_unread_report_count') {
    $requester = isset($_GET['requester']) ? trim($_GET['requester']) : '';
    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'success', 'count' => 0]);
    }
    $reports = loadReportsData($reportsFile);
    $meta = loadAdminMetaData($adminMetaFile);
    $lastRead = isset($meta['reports_last_read']) ? intval($meta['reports_last_read']) : 0;

    $unreadCount = 0;
    foreach ($reports as $r) {
        $time = isset($r['timestamp']) ? intval($r['timestamp']) : 0;
        if ($time > $lastRead) {
            $unreadCount++;
        }
    }
    sendJsonResponse(['status' => 'success', 'count' => $unreadCount]);
}

if ($action === 'submit_report') {
    $input = json_decode(file_get_contents('php://input'), true);
    $reporter = isset($input['reporter']) ? trim($input['reporter']) : '';
    $reportedUser = isset($input['reported_user']) ? trim($input['reported_user']) : '';
    $details = isset($input['details']) ? trim($input['details']) : '';

    if (empty($reporter) || empty($reportedUser) || empty($details)) {
        sendJsonResponse(['status' => 'error', 'message' => 'Missing report details'], 400);
    }

    $reports = loadReportsData($reportsFile);
    $reports[] = [
        'reporter' => $reporter,
        'reported_user' => $reportedUser,
        'details' => $details,
        'time' => date('Y-m-d h:i A'),
        'timestamp' => time()
    ];
    file_put_contents($reportsFile, json_encode($reports, JSON_PRETTY_PRINT));
    sendJsonResponse(['status' => 'success', 'message' => 'Report submitted successfully']);
}

if ($action === 'admin_manage_ban') {
    $input = json_decode(file_get_contents('php://input'), true);
    $requester = isset($input['requester']) ? trim($input['requester']) : '';
    if ($requester !== 'YourLocalHomeInvader') {
        sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized access'], 403);
    }

    $targetUser = isset($input['target_user']) ? trim($input['target_user']) : '';
    $targetIp = isset($input['target_ip']) ? trim($input['target_ip']) : '';
    $actionType = isset($input['ban_action']) ? trim($input['ban_action']) : '';

    $usersData = loadUsersData($usersFile);
    $bansData = loadBansData($bansFile);

    if ($actionType === 'ban_user' && !empty($targetUser) && isset($usersData[$targetUser])) {
        $usersData[$targetUser]['is_banned'] = true;
        file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => "User {$targetUser} banned"]);
    } elseif ($actionType === 'unban_user' && !empty($targetUser) && isset($usersData[$targetUser])) {
        $usersData[$targetUser]['is_banned'] = false;
        file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => "User {$targetUser} unbanned"]);
    } elseif ($actionType === 'ban_ip' && !empty($targetIp)) {
        if (!in_array($targetIp, $bansData['ips'])) {
            $bansData['ips'][] = $targetIp;
            file_put_contents($bansFile, json_encode($bansData, JSON_PRETTY_PRINT));
        }
        sendJsonResponse(['status' => 'success', 'message' => "IP {$targetIp} banned"]);
    } elseif ($actionType === 'unban_ip' && !empty($targetIp)) {
        $bansData['ips'] = array_values(array_diff($bansData['ips'], [$targetIp]));
        file_put_contents($bansFile, json_encode($bansData, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => "IP {$targetIp} unbanned"]);
    }

    sendJsonResponse(['status' => 'error', 'message' => 'Invalid ban parameters'], 400);
}

if ($action === 'register_user') {
    $input = json_decode(file_get_contents('php://input'), true);
    $clientIp = getClientIP();

    if (isIpBanned($clientIp, $bansFile)) {
        sendJsonResponse(['status' => 'error', 'message' => 'Access denied. Your IP address is banned.'], 403);
    }

    if ($input && !empty($input['username']) && !empty($input['password'])) {
        $usersData = loadUsersData($usersFile);
        $username = trim($input['username']);
        
        if (isset($usersData[$username])) {
            sendJsonResponse(['status' => 'error', 'message' => 'Username already exists or is reserved'], 400);
        }

        $usersData[$username] = [
            'password' => password_hash($input['password'], PASSWORD_DEFAULT),
            'vault_password' => null,
            'ips' => [$clientIp],
            'is_banned' => false
        ];
        file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));
        
        $userDir = $secureUploadsDir . preg_replace('/[^a-zA-Z0-9_\-]/', '', $username) . '/';
        if (!file_exists($userDir)) { @mkdir($userDir, 0755, true); }

        sendJsonResponse(['status' => 'success', 'username' => $username, 'ips' => [$clientIp]]);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Invalid registration'], 400);
}

if ($action === 'login_user') {
    $input = json_decode(file_get_contents('php://input'), true);
    $clientIp = getClientIP();

    if (isIpBanned($clientIp, $bansFile)) {
        sendJsonResponse(['status' => 'error', 'message' => 'Access denied. Your IP address is banned.'], 403);
    }

    if ($input && !empty($input['username']) && !empty($input['password'])) {
        $username = trim($input['username']);
        $usersData = loadUsersData($usersFile);

        if (isset($usersData[$username])) {
            if (!empty($usersData[$username]['is_banned'])) {
                sendJsonResponse(['status' => 'error', 'message' => 'This account has been banned.'], 403);
            }

            if (password_verify($input['password'], $usersData[$username]['password'])) {
                logUserIp($usersData, $username, $clientIp);
                file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));

                sendJsonResponse(['status' => 'success', 'username' => $username, 'ips' => $usersData[$username]['ips']]);
            }
        }
        sendJsonResponse(['status' => 'error', 'message' => 'Invalid credentials'], 401);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Invalid request'], 400);
}

if ($action === 'check_vault_pass') {
    $user = isset($_GET['user']) ? trim($_GET['user']) : '';
    $usersData = loadUsersData($usersFile);
    $hasPass = (!empty($user) && isset($usersData[$user]) && !empty($usersData[$user]['vault_password']));
    sendJsonResponse(['status' => 'success', 'has_vault_pass' => $hasPass]);
}

if ($action === 'set_vault_pass') {
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input && !empty($input['username']) && !empty($input['vault_password'])) {
        $username = trim($input['username']);
        $usersData = loadUsersData($usersFile);
        if (!isset($usersData[$username])) { 
            $usersData[$username] = ['password' => '', 'vault_password' => null, 'ips' => [getClientIP()], 'is_banned' => false]; 
        }
        $usersData[$username]['vault_password'] = password_hash($input['vault_password'], PASSWORD_DEFAULT);
        logUserIp($usersData, $username, getClientIP());
        file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => 'Vault password set']);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Failed to set password'], 400);
}

if ($action === 'verify_vault_pass') {
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input && !empty($input['username']) && !empty($input['vault_password'])) {
        $username = trim($input['username']);
        $usersData = loadUsersData($usersFile);
        if (isset($usersData[$username]) && !empty($usersData[$username]['vault_password'])) {
            if (password_verify($input['vault_password'], $usersData[$username]['vault_password'])) {
                logUserIp($usersData, $username, getClientIP());
                file_put_contents($usersFile, json_encode($usersData, JSON_PRETTY_PRINT));
                sendJsonResponse(['status' => 'success']);
            }
        }
        sendJsonResponse(['status' => 'error', 'message' => 'Invalid passphrase'], 401);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Invalid request'], 400);
}

if ($action === 'get_messages') {
    $msgs = file_exists($messagesFile) ? json_decode(file_get_contents($messagesFile), true) ?: [] : [];
    sendJsonResponse(['status' => 'success', 'messages' => $msgs]);
}

if ($action === 'post_message') {
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input && isset($input['sender'])) {
        $recipient = isset($input['recipient']) ? $input['recipient'] : 'general';
        
        if ($recipient === 'rules' && $input['sender'] !== 'YourLocalHomeInvader') {
            sendJsonResponse(['status' => 'error', 'message' => 'The rules channel is read-only.'], 403);
        }

        $msgs = file_exists($messagesFile) ? json_decode(file_get_contents($messagesFile), true) ?: [] : [];
        $newMsg = [
            'sender' => $input['sender'],
            'recipient' => $recipient,
            'ciphertext' => isset($input['ciphertext']) ? $input['ciphertext'] : '',
            'iv' => isset($input['iv']) ? $input['iv'] : '',
            'media_url' => isset($input['media_url']) ? $input['media_url'] : null,
            'media_type' => isset($input['media_type']) ? $input['media_type'] : null,
            'media_name' => isset($input['media_name']) ? $input['media_name'] : 'attachment',
            'time' => date('h:i A'),
            'timestamp' => time()
        ];
        $msgs[] = $newMsg;
        file_put_contents($messagesFile, json_encode($msgs, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => $newMsg]);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Invalid payload'], 400);
}

if ($action === 'mark_read') {
    $input = json_decode(file_get_contents('php://input'), true);
    $reader = isset($input['reader']) ? trim($input['reader']) : '';
    $partner = isset($input['partner']) ? trim($input['partner']) : '';

    if (!empty($reader) && !empty($partner)) {
        $lastRead = loadLastReadData($lastReadFile);
        if (!isset($lastRead[$reader])) $lastRead[$reader] = [];
        $lastRead[$reader][$partner] = time();
        file_put_contents($lastReadFile, json_encode($lastRead, JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success']);
    }
    sendJsonResponse(['status' => 'error'], 400);
}

if ($action === 'get_unread_counts') {
    $user = isset($_GET['user']) ? trim($_GET['user']) : '';
    if (empty($user)) {
        sendJsonResponse(['status' => 'success', 'counts' => []]);
    }
    $msgs = file_exists($messagesFile) ? json_decode(file_get_contents($messagesFile), true) ?: [] : [];
    $lastRead = loadLastReadData($lastReadFile);
    $userReadMap = $lastRead[$user] ?? [];

    $counts = [];
    foreach ($msgs as $m) {
        $sender = $m['sender'] ?? '';
        $recipient = $m['recipient'] ?? 'general';
        $timestamp = $m['timestamp'] ?? 0;

        if ($recipient === $user && $sender !== $user) {
            $lastTime = $userReadMap[$sender] ?? 0;
            if ($timestamp > $lastTime) {
                if (!isset($counts[$sender])) $counts[$sender] = 0;
                $counts[$sender]++;
            }
        }
    }
    sendJsonResponse(['status' => 'success', 'counts' => $counts]);
}

if ($action === 'delete_message') {
    $input = json_decode(file_get_contents('php://input'), true);
    $requester = isset($input['requester']) ? trim($input['requester']) : '';
    $msgIndex = isset($input['msg_index']) ? intval($input['msg_index']) : -1;
    $clearGeneral = isset($input['clear_general']) ? (bool)$input['clear_general'] : false;

    $msgs = file_exists($messagesFile) ? json_decode(file_get_contents($messagesFile), true) ?: [] : [];

    if ($clearGeneral) {
        if ($requester !== 'YourLocalHomeInvader') {
            sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized'], 403);
        }
        $filtered = [];
        foreach ($msgs as $m) {
            $rec = isset($m['recipient']) ? $m['recipient'] : 'general';
            if ($rec !== 'general') {
                $filtered[] = $m;
            }
        }
        file_put_contents($messagesFile, json_encode(array_values($filtered), JSON_PRETTY_PRINT));
        sendJsonResponse(['status' => 'success', 'message' => 'General channel cleared']);
    }

    if ($msgIndex >= 0 && isset($msgs[$msgIndex])) {
        $targetMsg = $msgs[$msgIndex];
        $sender = $targetMsg['sender'] ?? '';
        $recipient = $targetMsg['recipient'] ?? 'general';

        $isAdmin = ($requester === 'YourLocalHomeInvader');
        $isOwner = ($requester === $sender);

        if ($recipient === 'rules') {
            sendJsonResponse(['status' => 'error', 'message' => 'Cannot delete rules'], 403);
        }

        if ($isAdmin || ($isOwner && $recipient !== 'rules')) {
            array_splice($msgs, $msgIndex, 1);
            file_put_contents($messagesFile, json_encode(array_values($msgs), JSON_PRETTY_PRINT));
            sendJsonResponse(['status' => 'success', 'message' => 'Message deleted']);
        } else {
            sendJsonResponse(['status' => 'error', 'message' => 'Unauthorized to delete this message'], 403);
        }
    }

    sendJsonResponse(['status' => 'error', 'message' => 'Invalid delete request'], 400);
}

if ($action === 'chat_upload') {
    $chatMediaDir = $secureUploadsDir . 'chat_media/';
    if (!file_exists($chatMediaDir)) { @mkdir($chatMediaDir, 0755, true); }

    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $originalName = basename($_FILES['file']['name']);
        $fileName = time() . '_' . bin2hex(random_bytes(6)) . '.enc';
        $target = $chatMediaDir . $fileName;

        if (@move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            sendJsonResponse([
                'status' => 'success',
                'url' => 'api.php?action=get_media&file=' . urlencode($fileName),
                'name' => $originalName
            ]);
        }
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Failed to save chat media'], 400);
}

if ($action === 'get_media') {
    $file = isset($_GET['file']) ? basename($_GET['file']) : '';
    $filePath = $secureUploadsDir . 'chat_media/' . $file;
    if ($file && file_exists($filePath)) {
        if (ob_get_length()) ob_clean();
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }
    sendJsonResponse(['status' => 'error', 'message' => 'File not found'], 404);
}

$requestUser = isset($_GET['user']) ? preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['user']) : '';
$userVaultDir = !empty($requestUser) ? $secureUploadsDir . $requestUser . '/' : '';
if (!empty($userVaultDir) && !file_exists($userVaultDir)) {
    @mkdir($userVaultDir, 0755, true);
}

if ($action === 'list') {
    $files = [];
    if (!empty($userVaultDir) && file_exists($userVaultDir)) {
        $scanned = array_diff(scandir($userVaultDir), array('..', '.'));
        foreach ($scanned as $f) {
            $path = $userVaultDir . $f;
            if (is_file($path)) {
                $files[] = [
                    'id' => md5($f),
                    'name' => $f,
                    'size' => filesize($path),
                    'date' => date("n/j/Y", filemtime($path)),
                    'url' => 'api.php?action=get_vault_file&user=' . urlencode($requestUser) . '&file=' . urlencode($f)
                ];
            }
        }
    }
    sendJsonResponse(['status' => 'success', 'files' => $files]);
}

if ($action === 'get_vault_file') {
    $file = isset($_GET['file']) ? basename($_GET['file']) : '';
    $filePath = $userVaultDir . $file;
    if (!empty($requestUser) && $file && file_exists($filePath)) {
        if (ob_get_length()) ob_clean();
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }
    sendJsonResponse(['status' => 'error', 'message' => 'File not found'], 404);
}

if ($action === 'upload') {
    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK && !empty($requestUser)) {
        $fileName = basename($_FILES['file']['name']);
        $target = $userVaultDir . $fileName;
        if (@move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            sendJsonResponse(['status' => 'success', 'message' => 'Uploaded', 'file' => $fileName]);
        }
    }
    sendJsonResponse(['status' => 'error', 'message' => 'Upload failed.'], 400);
}

if ($action === 'delete') {
    $fileToDelete = isset($_GET['file']) ? basename($_GET['file']) : '';
    $path = $userVaultDir . $fileToDelete;
    if (!empty($requestUser) && $fileToDelete && file_exists($path)) {
        @unlink($path);
        sendJsonResponse(['status' => 'success']);
    }
    sendJsonResponse(['status' => 'error', 'message' => 'File not found'], 404);
}

sendJsonResponse(['status' => 'success', 'message' => 'BIN Secure API Operational']);
?>