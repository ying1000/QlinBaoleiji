#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "list.h"
#include "trie.h"

/* Global Var */
int lock_fd;
int menu_mode, manual_mode;
int suser_strategy_flag, group_strategy_flag, svrip_strategy_flag;
int fixed_password_flag, force_strategy_flag;
char suser_name[USERNAME_MAX], group_name[32], svrip_addr[64], passphrase[PASSWORD_MAX];
char admin_email[128], password_email[128];

/* Global Var */

int process(void);

int
print_usage()
{
	fprintf(stderr,
			"usage: %s [-fmh] [-u username] [-p password] [-g server_group] [-s server_ip]\n",
			PROGRAM_NAME);
	exit(-1);
}

int
main(int argc, char *argv[], char *envp[])
{
	extern int opterr, optind, optopt;
	extern char *optarg;
	int option;

	init_set_proc_title(argc, argv, envp);

	opterr = 0;

	while ((option = getopt(argc, argv, "u:p:g:s:mfch")) != -1)
	{
		switch (option)
		{
		case ('u'):
			suser_strategy_flag = 1;
			bzero(suser_name, sizeof(suser_name));
			strcpy(suser_name, optarg);
			break;
		case ('p'):
			fixed_password_flag = 1;
			bzero(passphrase, sizeof(passphrase));
			strcpy(passphrase, optarg);
			break;
		case ('g'):
			group_strategy_flag = 1;
			bzero(group_name, sizeof(group_name));
			strcpy(group_name, optarg);
			break;
		case ('s'):
			svrip_strategy_flag = 1;
			bzero(svrip_addr, sizeof(svrip_addr));
			strcpy(svrip_addr, optarg);
			break;
		case ('m'):
			menu_mode = 1;
			break;
		case ('f'):
			force_strategy_flag = 1;
			break;
		case ('c'):
			manual_mode = 1;
			break;
		case ('h'):
			print_usage();
			break;
		default:
			print_usage();
			break;
		}
	}

	if (group_strategy_flag == 1 && svrip_strategy_flag == 1)
	{
		fprintf(stderr, "Parameter conflicts.\n");
		return -1;
	}

	if ((lock_fd = test_lock()) == -1)
	{
		fprintf(stderr, "Process conflicts.\n");
		return -1;
	}

	if (read_config() == -1)
	{
		fprintf(stderr, "Can't read config file.\n");
		return -1;
	}

	if (init_log() == -1)
	{
		fprintf(stderr, "Can't open log file.\n");
		return -1;
	}

	process();

	return 0;
}
