<?php
declare(strict_types=1);

/*
 * Riaya API foundation.
 * Requires PHP 8+, PDO SQLite, and a same-origin deployment.
 * Configure CRECHE_DB_PATH and CRECHE_SETUP_TOKEN in the server environment.
 */
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'secure' => $isHttps,
    'samesite' => 'Strict',
    'path' => '/',
]);
session_start();

function respond(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function body(): array {
    $data = json_decode(file_get_contents('php://input') ?: '{}', true);
    return is_array($data) ? $data : [];
}
function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $path = getenv('CRECHE_DB_PATH') ?: dirname(__DIR__) . '/storage/riaya.sqlite';
    $dir = dirname($path);
    if (!is_dir($dir)) mkdir($dir, 0700, true);
    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','parent','teacher')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS children (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        name TEXT NOT NULL,
        birth_date TEXT,
        group_name TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        child_id INTEGER NOT NULL REFERENCES children(id) ON DELETE CASCADE,
        attendance_date TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('present','absent','late')),
        arrival_time TEXT,
        UNIQUE(child_id, attendance_date)
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        child_id INTEGER NOT NULL REFERENCES children(id) ON DELETE CASCADE,
        amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
        payment_month TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','rejected')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
    return $pdo;
}
function currentUser(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $q = db()->prepare('SELECT id, name, email, role FROM users WHERE id = ?');
    $q->execute([$_SESSION['user_id']]);
    return $q->fetch() ?: null;
}
function requireRole(array $roles): array {
    $user = currentUser();
    if (!$user) respond(401, ['error' => 'يلزم تسجيل الدخول']);
    if (!in_array($user['role'], $roles, true)) respond(403, ['error' => 'ليس لديك صلاحية لهذه العملية']);
    return $user;
}
function requireCsrf(): void {
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $saved = $_SESSION['csrf'] ?? '';
    if (!$saved || !$sent || !hash_equals($saved, $sent)) {
        respond(419, ['error' => 'انتهت صلاحية الجلسة، حدّث الصفحة وحاول مجددًا']);
    }
}

$pdo = db();
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($action === 'setup' && $method === 'POST') {
    $data = body();
    $expected = getenv('CRECHE_SETUP_TOKEN') ?: '';
    if (strlen($expected) < 24 || !hash_equals($expected, (string)($data['setup_token'] ?? ''))) {
        respond(403, ['error' => 'رمز الإعداد غير صحيح أو غير مضبوط على الخادم']);
    }
    if ((int)$pdo->query('SELECT COUNT(*) FROM users WHERE role = "admin"')->fetchColumn() > 0) {
        respond(409, ['error' => 'تم إنشاء حساب الإدارة بالفعل']);
    }
    $name = trim((string)($data['name'] ?? ''));
    $email = strtolower(trim((string)($data['email'] ?? '')));
    $password = (string)($data['password'] ?? '');
    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 12) {
        respond(422, ['error' => 'أدخل اسمًا وبريدًا صحيحًا وكلمة مرور من 12 حرفًا على الأقل']);
    }
    $q = $pdo->prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)');
    try { $q->execute([$name, $email, password_hash($password, PASSWORD_DEFAULT), 'admin']); }
    catch (PDOException $e) { respond(409, ['error' => 'البريد الإلكتروني مستخدم بالفعل']); }
    respond(201, ['message' => 'تم إنشاء حساب الإدارة. احذف رمز الإعداد من بيئة التشغيل بعد الاستخدام.']);
}

if ($action === 'login' && $method === 'POST') {
    $data = body();
    $email = strtolower(trim((string)($data['email'] ?? '')));
    $password = (string)($data['password'] ?? '');
    $q = $pdo->prepare('SELECT id, password_hash FROM users WHERE email = ?');
    $q->execute([$email]);
    $record = $q->fetch();
    if (!$record || !password_verify($password, $record['password_hash'])) {
        usleep(250000);
        respond(401, ['error' => 'البريد الإلكتروني أو كلمة المرور غير صحيحة']);
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$record['id'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    respond(200, ['user' => currentUser(), 'csrf' => $_SESSION['csrf']]);
}
if ($action === 'me' && $method === 'GET') {
    $user = currentUser();
    if (!$user) respond(401, ['error' => 'يلزم تسجيل الدخول']);
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    respond(200, ['user' => $user, 'csrf' => $_SESSION['csrf']]);
}
if ($action === 'logout' && $method === 'POST') {
    requireCsrf();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', ['expires' => time()-42000, 'path' => $p['path'], 'secure' => $p['secure'], 'httponly' => true, 'samesite' => 'Strict']);
    }
    session_destroy();
    respond(200, ['message' => 'تم تسجيل الخروج']);
}
if ($action === 'users' && $method === 'POST') {
    requireRole(['admin']);
    requireCsrf();
    $data = body();
    $name = trim((string)($data['name'] ?? ''));
    $email = strtolower(trim((string)($data['email'] ?? '')));
    $password = (string)($data['password'] ?? '');
    $role = (string)($data['role'] ?? 'parent');
    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 12 || !in_array($role, ['parent','teacher'], true)) {
        respond(422, ['error' => 'بيانات الحساب غير صالحة؛ كلمة المرور يجب أن تكون 12 حرفًا على الأقل']);
    }
    try {
        $q = $pdo->prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)');
        $q->execute([$name, $email, password_hash($password, PASSWORD_DEFAULT), $role]);
    } catch (PDOException $e) { respond(409, ['error' => 'البريد الإلكتروني مستخدم بالفعل']); }
    respond(201, ['id' => (int)$pdo->lastInsertId(), 'name' => $name, 'email' => $email, 'role' => $role]);
}
if ($action === 'children' && $method === 'GET') {
    $user = requireRole(['admin','parent','teacher']);
    if ($user['role'] === 'admin') {
        $rows = $pdo->query('SELECT c.id,c.name,c.birth_date,c.group_name,c.parent_id,u.name AS parent_name FROM children c JOIN users u ON u.id=c.parent_id ORDER BY c.id DESC')->fetchAll();
    } else {
        $q = $pdo->prepare('SELECT c.id,c.name,c.birth_date,c.group_name,c.parent_id,u.name AS parent_name FROM children c JOIN users u ON u.id=c.parent_id WHERE c.parent_id=? ORDER BY c.id DESC');
        $q->execute([$user['id']]); $rows = $q->fetchAll();
    }
    respond(200, ['children' => $rows]);
}
if ($action === 'children' && $method === 'POST') {
    requireRole(['admin']); requireCsrf();
    $data = body();
    $parentId = filter_var($data['parent_id'] ?? null, FILTER_VALIDATE_INT);
    $name = trim((string)($data['name'] ?? ''));
    $birthDate = trim((string)($data['birth_date'] ?? ''));
    $group = trim((string)($data['group_name'] ?? ''));
    if (!$parentId || $name === '') respond(422, ['error' => 'اسم الطفل وحساب الولي مطلوبان']);
    $q = $pdo->prepare("SELECT id FROM users WHERE id=? AND role='parent'");
    $q->execute([$parentId]);
    if (!$q->fetch()) respond(422, ['error' => 'حساب الولي غير موجود']);
    $q = $pdo->prepare('INSERT INTO children(parent_id,name,birth_date,group_name) VALUES(?,?,?,?)');
    $q->execute([$parentId,$name,$birthDate ?: null,$group]);
    respond(201, ['id'=>(int)$pdo->lastInsertId()]);
}
if ($action === 'attendance' && $method === 'POST') {
    requireRole(['admin','teacher']); requireCsrf();
    $data = body();
    $childId = filter_var($data['child_id'] ?? null, FILTER_VALIDATE_INT);
    $date = (string)($data['date'] ?? date('Y-m-d'));
    $status = (string)($data['status'] ?? '');
    $time = trim((string)($data['arrival_time'] ?? ''));
    if (!$childId || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) || !in_array($status,['present','absent','late'],true)) {
        respond(422, ['error' => 'بيانات الحضور غير صالحة']);
    }
    $q = $pdo->prepare('INSERT INTO attendance(child_id,attendance_date,status,arrival_time) VALUES(?,?,?,?) ON CONFLICT(child_id,attendance_date) DO UPDATE SET status=excluded.status,arrival_time=excluded.arrival_time');
    $q->execute([$childId,$date,$status,$time ?: null]);
    respond(200, ['message' => 'تم حفظ الحضور']);
}
if ($action === 'payments' && $method === 'GET') {
    $user = requireRole(['admin','parent']);
    if ($user['role'] === 'admin') {
        $rows = $pdo->query('SELECT p.id,p.child_id,c.name AS child_name,p.amount_cents,p.payment_month,p.status FROM payments p JOIN children c ON c.id=p.child_id ORDER BY p.id DESC')->fetchAll();
    } else {
        $q = $pdo->prepare('SELECT p.id,p.child_id,c.name AS child_name,p.amount_cents,p.payment_month,p.status FROM payments p JOIN children c ON c.id=p.child_id WHERE c.parent_id=? ORDER BY p.id DESC');
        $q->execute([$user['id']]); $rows = $q->fetchAll();
    }
    respond(200, ['payments' => $rows]);
}

respond(404, ['error' => 'المسار المطلوب غير موجود']);
