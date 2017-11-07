#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mysql.h"

typedef struct _candidate
{
	int id;
	int port;
	int login_method;
	int padding;
	char username[256];
	char ipaddr[256];
	char cur_password[256];
	char old_password[256];
	char new_password[256];
	char **av;
}CANDIDATE;


#define SSH_LOGIN_TIMEOUT 20
#define SSH_INPUT_TIMEOUT 3
#define BINARY_PATH "/opt/freesvr/audit/passwd/sbin/"
