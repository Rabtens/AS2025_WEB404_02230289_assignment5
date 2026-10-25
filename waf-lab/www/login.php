<?php
// Demo only: builds the kind of SQL string a vulnerable app would build,
// but NEVER sends it to a database. It just shows what would have run.
$user = isset($_REQUEST['username']) ? $_REQUEST['username'] : '';
$pass = isset($_REQUEST['password']) ? $_REQUEST['password'] : '';
$submitted = ($user !== '' || $pass !== '');
$query = "SELECT * FROM users WHERE username='" . $user . "' AND password='" . $pass . "'";
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title></head>
<body style="font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto;">
  <h1>Login</h1>
  <form method="POST" action="login.php">
    <p><label>Username <input type="text" name="username"></label></p>
    <p><label>Password <input type="password" name="password"></label></p>
    <button type="submit">Log in</button>
  </form>
  <?php if ($submitted): ?>
    <p>Query that a vulnerable app would have run (not executed):</p>
    <pre><?php echo htmlspecialchars($query); ?></pre>
  <?php endif; ?>
  <p><a href="index.html">Back</a></p>
</body>
</html>
