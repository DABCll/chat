Alpha

Requires LIBSSH

makefile is for refernece, please build with gcc for testing 

build: 'gcc -lssh "source.c" -o "bin name"'

Auth.c ONLY TESTS LIB SSH with localhost on port 22  

Pssnate.c is a wrapper for ssh using the libssh (basic password auth)

usage './Pssnate -h "user@host OR host" -p "port" -u "user"(if not set in host opt)'

*update*

append '-c "COMMAND"' to exec a command

ADDED MACRO DEBUG default: 3

