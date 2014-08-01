#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

/****************************************************
**                    Auth.c                       **
**                                                 **
** Date: 7/31/14                                   **
**                                                 **
** Comments: Test for SSH auth using the libssh    **
****************************************************/


  /*    \ _____ _/  |_  ____ 
 /   |   \\__  \\   __\/ __ \
/    |    \/ __ \|  | \  ___/
\____|__  (____  /__|  \___  >
        \/     \/         */


/////////////////////////////////////////////////////////
//This Fucntion is taken from the libssh documentation//
//For the most part...                               //
//////////////////////////////////////////////////////

int verifyHost(ssh_session session)
{
	int check, hashLen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];
	check = ssh_is_server_known(session);
	hashLen = ssh_get_pubkey_hash(session, &hash);
	if(hashLen < 0)
		return -1;
	switch(check){
	case SSH_SERVER_KNOWN_OK:
		break;
	case SSH_SERVER_KNOWN_CHANGED:
		fprintf(stderr, "Host Changed\n");
		ssh_print_hexa("Pub Key Hash", hash, hashLen);
		fprintf(stderr, "Session will be stopped\n");
		free(hash);
		return -1;
	case SSH_SERVER_FOUND_OTHER:
		fprintf(stderr, "The host key is not found\n");
		free(hash);
		return -1;
	case SSH_SERVER_FILE_NOT_FOUND:
		fprintf(stderr, "Could not Find know host file");
	case SSH_SERVER_NOT_KNOWN:
		hexa = ssh_get_hexa(hash,hashLen);
		fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        free(hexa);
        if (fgets(buf, sizeof(buf), stdin) == NULL)
        {
            free(hash);
            return -1;
        }
        if (strncasecmp(buf, "yes", 3) != 0)
        {
            free(hash);
            return -1;
        }
        if (ssh_write_knownhost(session) < 0)
        {
            fprintf(stderr, "Error %s\n", strerror(errno));
            free(hash);
            return -1;
        }
        break;
    case SSH_SERVER_ERROR:
        fprintf(stderr, "Error %s", ssh_get_error(session));
        free(hash);
        return -1;
    }
    free(hash);
    return 0;
}

int main(int argc, char *argv[])
{
    ssh_session sshSession;
	int check;
	char *passWord, *host = NULL, *buf = NULL, *user = NULL;
	int opt, port = 0;

	while((opt = getopt (argc, argv, "h:p:u:")) != -1){
		switch(opt){
		case 'h':
			host = optarg;
			break;
		case 'p':
			buf = optarg;
			port = atoi(buf);
			break;
		case 'u':
			user = optarg;
			break;
		}
	}
			
	//////////////////////////////
	//Open session & set options//
	//////////////////////////////

	if(host){
		sshSession = ssh_new();
		if(sshSession == NULL)
			exit(-1);
		ssh_options_set(sshSession, SSH_OPTIONS_HOST, host);
	}
	else if(!host){
		sshSession = ssh_new();
        if(sshSession == NULL)
            exit(-1);
        ssh_options_set(sshSession, SSH_OPTIONS_HOST, "localhost");
	}
	if(port)
		ssh_options_set(sshSession, SSH_OPTIONS_PORT, &port);
	if(user)
		ssh_options_set(sshSession, SSH_OPTIONS_USER, user);

	//////////////////////
	//Connect to server//
	////////////////////

	check = ssh_connect(sshSession);
	if(check != SSH_OK){
		fprintf(stderr, "Error connectiong to host: %s\n",
				ssh_get_error(sshSession));
		ssh_free(sshSession);
		exit(-1);
	}

	////////////////////////////////
	//Verify the servers identity//
	//////////////////////////////

	if(verifyHost(sshSession) < 0){
		ssh_disconnect(sshSession);
		ssh_free(sshSession);
		exit(-1);
	}

	///////////////////////////
	//Authenticate ourselves//
	/////////////////////////

	passWord = getpass("Password: ");
	check = ssh_userauth_password(sshSession, NULL, passWord);
	if(check != SSH_AUTH_SUCCESS){
	fprintf(stderr, "Error authenticating with password: %s\n",
			ssh_get_error(sshSession));
	ssh_disconnect(sshSession);
	ssh_free(sshSession);
	exit(-1);
}

ssh_disconnect(sshSession);
ssh_free(sshSession);

    return 0;
}
