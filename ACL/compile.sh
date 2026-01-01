#!/bin/sh

# This script compiles the revoke_acl.c script into a static binary executable
# We have to use a C file because Alpine linux doesn't use glibc (since it uses BusyBox), and we need an executable to SUID
# And we must create this executable as an entrypoint because Docker's build process doesn't preserve ACLs (renders it useless)
# It's annoying, I know.

gcc -static -o ./revoke_acl ./revoke_acl.c