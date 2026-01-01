#!/bin/sh

# The main thing this does is:
    # 1. Prevents node from executing or writing ANYTHING on the file system (except specific ftyeet directories)
    # 2. Prevents node from running bash commands (especially $chmod)
setfacl -m u:node:r-- /
setfacl -R -m u:node:r-- /bin /lib /opt /root /sbin /srv /tmp /var /usr

# Allow them to run one command (npm)
setfacl -m u:node:rx /usr/local/bin/npm   

# Allow the user to selectively read, write, and query user-uploaded files in $files
chmod 777 /usr/src/app/Site/files       # execute for dir --> can $ls
setfacl -m u:node:r-x /usr/src/app/Site/files       # This is the directory!
setfacl -d -m u:node:rw- /usr/src/app/Site/files/

# Prevents all newly created files from having execute perms
# This is important because setfacl doesn't affect file owners
# Note: $chmod is already banned by setfacl on /bin
umask 022

# Debug
setfacl -R -m u:node:r-x /bin/sh