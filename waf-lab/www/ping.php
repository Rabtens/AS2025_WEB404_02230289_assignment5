<?php
// Demo only: shows the command a vulnerable app might build. It is NEVER executed.
$host = isset($_GET['host']) ? $_GET['host'] : 'localhost';
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Ping</title></head>
<body style="font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto;">
  <h1>Ping</h1>
  <p>A vulnerable app might have run: <code>ping -c 1 <?php echo htmlspecialchars($host); ?></code> (not executed here)</p>
  <p><a href="index.html">Back</a></p>
</body>
</html>
