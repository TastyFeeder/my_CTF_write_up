<?php

$FROM_INCLUDE = true;

$pages = array(
    // disabled
    // "upload_snoopy" => "Uploads",
    "about" => "About"
);

if (isset($_GET["p"]))
    $p = $_GET["p"];
else
    $p = "home";


if(strlen($p) > 100)
{
    die("parameter is too long");
}

?>

<!DOCTYPE html>
<html lang="en">
<?php
include "header.php";
include $p . ".php";
?>
</body>
</html>
