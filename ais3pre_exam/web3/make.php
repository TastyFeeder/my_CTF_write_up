<?php

try{
    $p = new Phar("my.phar", 0, 'my.phar');
} catch (UnexpectedValueException $e) {
    die('Could not open my.phar');
} catch (BadMethodCallException $e) {
    echo 'technically, this cannot happen';
}

$p->startBuffering();
$p['a.php'] = 'a'; 


// use my.phar
echo file_get_contents('phar://my.phar/file2.txt');  // echo file2

// make a file named my.phar
$p->setStub("<?php
    Phar::mapPhar('myphar.phar');  
__HALT_COMPILER();");

$p->stopBuffering();

?>