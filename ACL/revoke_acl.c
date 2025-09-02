#include <stdlib.h>
#include <unistd.h>

int main()
{
    seteuid(0); // Run as root

    /* The main thing this does is:
        1. Prevents node from executing or writing ANYTHING on the file system (except specific ftyeet directories)
        2. Prevents node from running bash commands (especially $chmod)*/
    system("sudo setfacl -m u:node:r-- /");
    system("setfacl -R -m u:node:r-- /bin /lib /opt /root /sbin /srv /tmp /var /usr");

    // Allow them to run one command (npm)
    system("setfacl -m u:node:rx /usr/local/bin/npm");

    //  Allow the user to selectively read, write, and query user-uploaded files in $files
    system("chmod 777 /usr/src/app/Site/files");                   // execute for dir --> can $ls
    system("setfacl -m u:node:r-x /usr/src/app/Site/files");       // This is the directory!
    system("setfacl -d -m u:node:rw- /usr/src/app/Site/files/");

    system("umask 022");

    // Debug
    system("setfacl -R -m u:node:r-x /bin/sh");

    return 0;
}