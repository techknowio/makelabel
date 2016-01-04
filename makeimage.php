<?php
$img = imagecreatetruecolor(320, 600);
$bg = imagecolorallocate ( $img, 255, 255, 255 );
imagefilledrectangle($img,0,0,320,600,$bg);

$im = imagecreatefrompng("public.png");
$text = 'This is your Public key';
$font = 'arial.ttf';
$black = imagecolorallocate($im, 0, 0, 0);
imagettftext($im, 20, 90, 10, 20, $black, $font, $text);

imagecopy($img, $im, 100, 0, 0, 0, 100, 100);

imagejpeg($img,"myimg.jpg",100);

imagedestroy($im);
imagedestroy($img);

?>
