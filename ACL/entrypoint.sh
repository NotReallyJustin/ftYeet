#!/bin/sh

# -------- root ----------

# The main thing this does is:
    # 1. Prevents node from executing or writing ANYTHING on the file system (except specific ftyeet directories)
    # 2. Prevents node from running bash commands (especially $chmod)
setfacl -R -m u:node:r-- /lib /opt /root /sbin /srv /var /tmp

# Allow them to run node and npm (kind of have to)
setfacl -R -x u:node /usr/local/lib/node_modules/
setfacl -m u:node:r-X /usr/local/bin/npm
setfacl -m u:node:r-x /usr/local/bin/node

# Allow the user to selectively read, write, and query user-uploaded files in $files
chmod 777 /usr/src/app/Site/files       # execute for dir --> can $ls
setfacl -m u:node:r-x /usr/src/app/Site/files       # This is the directory!
setfacl -d -m u:node:rw- /usr/src/app/Site/files/

# Prevents all newly created files from having execute perms
# This is important because setfacl doesn't affect file owners
# Note: $chmod is already banned by setfacl on /bin
umask 022

# Debug
setfacl -m u:node:r-x /bin/sh

# -------- node ----------
# exec su-exec node sh -c "cd /usr/src/app/Site && npm start"
exec su-exec node npm --prefix /usr/src/app/Site start