<?php

if (isset($_GET["p"]))
{
    $filename = "images/" . $_GET['p'];
    if (!is_file($filename))
    {
        echo "not found";
        exit();
    }

    $ext = pathinfo($filename, PATHINFO_EXTENSION);

    header("Content-Type: image/$ext");
    $data = file_get_contents($filename);
    echo $data;
}

?>
