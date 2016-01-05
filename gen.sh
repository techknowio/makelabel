#!/bin/bash
random=`openssl rand -base64 1024`
OUTPUT=`./paperwal.py -r $random --silent -p`
public=`echo $OUTPUT | cut -d "," -f 1`
private=`echo $OUTPUT | cut -d "," -f 2`
qrencode -s 6 -o public.png $public
qrencode -s 6 -o private.png $private
php makeimage.php
