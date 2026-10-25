<?php
// Demo only: shows the requested page name. It does NOT open any file.
$page = isset($_GET['page']) ? $_GET['page'] : 'about';
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>View</title></head>
<body style="font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto;">
  <h1>View page</h1>
  <p>A vulnerable app might have loaded the file: <code><?php echo htmlspecialchars($page); ?></code> (not opened here)</p>
  <p><a href="index.html">Back</a></p>
</body>
</html>
