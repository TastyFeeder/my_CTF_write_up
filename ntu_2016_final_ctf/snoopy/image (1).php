<?php
$images = scandir("images");
$images = array_diff($images, array('..', '.', 'flag.png'));
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Snoopys</title>
</head>

<body>
<div align="center">
<h1>
    So bored? So tired?<br/>
    Cheer up! Let me give you some Snoopy!!! <br/>
</h1>
<?php
foreach ($images as $f)
{
    echo "<img src='image.php?p=$f'></img><br/>\n";
}
?>
<h1>
    And ....... a flag!!!!!
</h1>
<img src='image.php?p=flag.png'></img><br/>
<br/>
<!--
    Still looking for something?
    Fine. I've already give you everything except an <a href="admin/">admin only</a> website.
    It is locked. :)
    My advise is just to give up and sleep.
-->
</div>


</body>

</html>
