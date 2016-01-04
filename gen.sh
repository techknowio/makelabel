#!/bin/bash
random=`openssl rand -base64 1024`
OUTPUT=`./paperwal.py -r $random --silent -p`
public=`echo $OUTPUT | cut -d "," -f 1`
private=`echo $OUTPUT | cut -d "," -f 2`
qrencode -o public.png $public
qrencode -o private.png $private

