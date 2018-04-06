#!/bin/bash

# Call this script once a day

restart=0
twentyFourHoursAgo=$(( `date "+%s"` - 86400 ))
for certTime in `stat -c "%Y" /etc/tomcat9/ssl/*/domain.crt`
do
    if (( $certTime > $twentyFourHoursAgo ))
    then
       restart=1
    fi
done
if (( 1 == $restart ))
then
   /usr/sbin/service tomcat9 restart
fi
