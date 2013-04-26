ssh YOURSERVER 2> /dev/null  'bash -s' < /opt/local/bin/ssl $1 $2 | xargs -I xx echo Remote: xx  && /opt/local/bin/ssl $1 $2 | xargs -I xx  echo Local: xx
