#!/bin/sh

FROM=`cat $HOME/.mailcheck/from`
TO=`cat $HOME/.mailcheck/to`

./sendEmail -s 127.0.0.1:2524 -f $FROM -t $TO -u "Testmail" -v -o tls=no -m "Mailtext" $@

