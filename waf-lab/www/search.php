<?php
// Intentionally unsafe demo page: reflects user input WITHOUT escaping,
// so a reflected XSS payload would run if the WAF let it through.
$q = isset($_GET['q']) ? $_GET['q'] : '';
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Search</title></head>
<body style="font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto;">
  <h1>Search</h1>
  <form method="GET" action="search.php">
    <input type="text" name="q" value="">
    <button type="submit">Search</button>
  </form>
  <p>You searched for: <?php echo $q; ?></p>
  <p><a href="index.html">Back</a></p>
</body>
</html>
