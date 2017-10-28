#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "config.h"
#include "log.h"
#include "flock.h"

#define USERNAME_MAX		64
#define PASSWORD_MAX		32

#define AGENT_PROTOCOL		0
#define SSH1_PROTOCOL		1
#define SSH2_PROTOCOL		2
#define TELNET_PROTOCOL		3
#define RADIUS_PROTOCOL		5
#define UNSUPPORT_PROTOCOL	4

typedef struct _info
{
	/* Device ip */
	char device_serverip[64];
	/* Last update time */
	char last_modify_day[32];
	/* Login username */
	char device_username[USERNAME_MAX];
	/* Current login password */
	char device_password[PASSWORD_MAX];
	/* Fixed or random new password */
	char modify_password[PASSWORD_MAX];
	/* Master username */
	char master_username[USERNAME_MAX];
	/* Master password */
	char master_password[PASSWORD_MAX];
	/* Port */
	int device_port;
	/* Login method, it means login protocol */
	int device_ptcl;
	/* Device type */
	int device_type;
	/* Auto modify */
	int auto_modify;
	/* Login protocol */
	int protocol;
	/* Have master */
	int have_master;
	/* Calc date for user define */
	int calc_date;
	/* Modify ret */
	int modify_result;
	/* Corresponding devices id */
	struct _list_node *id_list;
	/* Execv argv */
	char **argv;
	/* Command list */
	struct _command *input;
} Info;

extern int lock_fd;
extern int menu_mode, manual_mode;
extern int suser_strategy_flag, group_strategy_flag, svrip_strategy_flag;
extern int fixed_password_flag, force_strategy_flag;
extern char suser_name[USERNAME_MAX], group_name[32], svrip_addr[64], passphrase[PASSWORD_MAX];
extern char admin_email[128], password_email[128];
extern char    aes_key[256];

#endif
