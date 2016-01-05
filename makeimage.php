<?php
$img = imagecreatetruecolor(320, 600);
$bg = imagecolorallocate ( $img, 255, 255, 255 );
imagefilledrectangle($img,0,0,320,600,$bg);

$im = imagecreatefrompng("public.png");
$text = 'This is your Public key';
$font = 'arial.ttf';
$black = imagecolorallocate($im, 0, 0, 0);
imagettftext($img, 10, 270, 20, 50, $black, $font, $text);
$im = imagerotate($im,270,0);
imagecopy($img, $im, 30, 0, 0, 0, 222,222);
imagedestroy($im);

$im = imagecreatefrompng("private.png");
$text = 'This is your Private key';
$font = 'arial.ttf';
$black = imagecolorallocate($im, 0, 0, 0);
imagettftext($img, 10, 270, 20, 350, $black, $font, $text);
$im = imagerotate($im,270,0);
imagecopy($img, $im, 30, 300, 0, 0, 222,222);





imagejpeg($img,"myimg.jpg",100);

imagedestroy($im);
imagedestroy($img);

?>
