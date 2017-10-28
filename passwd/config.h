#ifndef CONFIG_H
#define CONFIG_H				/* + To stop multiple inclusions. + */

struct options
{
	char *log_file;
	char *licenses_file;
	char *licenses_device;
	int write_local_log;
	int write_syslog;
	int send_mail;
	char *audit_ip;
	int radius_flag;
	int radius_double;
	char *mradius_address;
	int mradius_port;
	char *mradius_secret;
	char *sradius_address;
	int sradius_port;
	char *sradius_secret;
	int radius_timeout;
	char *mysql_address;
	char *mysql_username;
	char *mysql_password;
	char *mysql_database;
	int delete_random;
	int authd_timeout;
	char *replay_address;
	char *replay_password;
	int replay_port;
	int random_timeout;
	int timeout;
	int retry_times;
    int udf;
};

extern struct options config;

int read_config(void);
int reload_config(void);

#endif
