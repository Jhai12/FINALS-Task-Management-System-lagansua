<?php
require_once __DIR__ . '/../itelec-2/database/dbconnection.php';

$token = filter_input(INPUT_GET, 'token');

if (!$token) {
    die("Invalid token.");
}

$token_hash = hash("sha256", $token);

$database = new Database();
$mysqli = $database->dbConnection(); 

$sql = "SELECT * FROM user WHERE reset_token_hash = ?";
$stmt = $mysqli->prepare($sql);

$stmt->bindValue(1, $token_hash, PDO::PARAM_STR);
$stmt->execute();

$result = $stmt->fetch(PDO::FETCH_ASSOC);

if ($result === false) {
    die("Token not found.");
}

if (strtotime($result["reset_token_expires_at"]) <= time()) {
    die("Token has expired.");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
</head>
<body>
    <h1>Reset Password</h1>
    <form action="dashboard/admin/authentication/admin-class.php" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token ?>">
        <input type="text" name="otp" placeholder="Enter OTP" required> <br> <br>
        <input type="password" name="new_password" placeholder="Enter New Password" required> <br> <br>
        <button type="submit" name="btn-reset-password">Reset Password</button>
    </form>
</body>
</html>
