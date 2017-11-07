#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "global.h"

char aes_key[256];

char **
execv_argument_create(const char *ip, const char *username, const char *password, int login_method, int port)
{
	char **argv, para[256];
	int i = 0, j = 0;
	int len = 512;

	if ((argv = (char **) malloc(sizeof(char *) * 16)) == NULL)
	{
		//write_log("Malloc (char **) execv argv failed.");
		return NULL;
	}

	for (i = 0; i < 16; i++)
	{
		if ((argv[i] = (char *) malloc(sizeof(char) * len)) == NULL)
		{
			for (j = 0; j < i; j++)
			{
				if (argv[j] != NULL)
					free(argv[j]);
			}

			if (argv != NULL)
				free(argv);

			//write_log("Malloc (char *) execv argv failed.");
			return NULL;
		}
		else
		{
			memset(argv[i], 0x00, len);
		}
	}

	i = -1;

	if (login_method != 5)
	{
		strcpy(argv[++i], "autossh");
	}
	else
	{
		strcpy(argv[++i], "telnet");
	}

	/* SSH1 */
	/*if (protocol == SSH1_PROTOCOL)
	{
		strcpy(argv[++i], "-1");
	}*/

	/* SSH pseudo tty */
	// if( protocol == SSH2_PROTOCOL )
	if (login_method != 5)
	{
		strcpy(argv[++i], "-tt");
	}

	strcpy(argv[++i], ip);

	/* Add port */
	/* Telnet */
	if (login_method == 5)
	{
		snprintf(argv[++i], len, "%d", port);
	}
	/* SSH */
	else
	{
		strcpy(argv[++i], "-p");
		snprintf(argv[++i], len, "%d", port);
	}

	/* Add -l username if username is not empty */
	if (login_method != 5 && username != NULL && strlen(username) != 0)
	{
		strcpy(argv[++i], "-l");
		strcpy(argv[++i], username);
	}

	/* Add -z password if protocol is SSH */
	if (login_method != 5)
	{
		strcpy(argv[++i], "-z");
		strcpy(argv[++i], password);

		bzero(para, sizeof(para));
		snprintf(para, sizeof(para), "-oConnectTimeout=%d", 60);
		strcpy(argv[++i], para);
	}

	argv[++i] = (char *) 0;

	//printf("%s %s %s %s %s %s %s\n", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
	return argv;
}

	ssize_t
writen(int fd, void *buf, size_t n)
{
	size_t tot = 0;
	ssize_t w;

	do
	{
		if ((w = write(fd, (void *) ((u_char *) buf + tot), n - tot)) <= 0)
			return (w);

		tot += w;
	}
	while (tot < n);

	return (tot);
}

	int
kill_child_process(int cid, int signo)
{
	kill(cid, signo);
	return 0;
}

	int
wait_child_process(int cid, int *code)
{
	wait(code);
	return 0;
}


	int
try_input_string(int cid, int ifd, int ofd, const char *string, int is_echo)
{
	fd_set rfds, rtmp;
	int nfd, ret, n, response = 0, len;
	struct timeval login_timeout;
	char buf[10240], *p;

	FD_ZERO(&rfds);
	FD_SET(ofd, &rfds);
	// FD_SET( efd, &rfds );
	// nfd = ( ofd > efd ? ofd : efd ) + 1;
	nfd = ofd + 1;

	/* Input command */
	bzero(buf, sizeof(buf));
	p = buf;
	len = sizeof(buf);

	writen(ifd, (void *) string, strlen(string));

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));
		login_timeout.tv_sec = SSH_INPUT_TIMEOUT;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Catch a signal from child process */
			if (errno == EINTR)
			{
				return -1;
			}
			return -1;
		}
		/* Timeout */
		else if (ret == 0)
		{
			/* Input command, require echo command */
			if (is_echo)
			{
				/* Maybe login successed */
				if (response == 1)
				{
					/* Echo is right, input enter */
					/* if (strcasecmp(buf, string) == 0) { break; } */
					// to do
					if (strcasestr(buf, string) != NULL)
					{
						break;
					}
					/* Echo is wrong, it's not a shell */
					else
					{
						fprintf(stderr, "Echo is wrong, it's not in a shell.\n");
						return -1;
					}
				}
				/* This is not a shell */
				else
				{
					fprintf(stderr, "No response of input command, exit.\n");
					return -1;
				}
			}
			/* Input password, require no echo the string */
			else
			{
				/* No echo is right */
				if (response == 0)
				{
					break;
				}
				/* Input the password in shell, passwd execute failed */
				else
				{
					fprintf(stderr, "Input the password in shell, passwd executed failed, exit.\n");
					return -1;
				}
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			n = read(ofd, p, len);

			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(2, p, n);
			}

			p = p + n;
			len = len - n;
		}

	}

	/* Input enter 0x0d */
	bzero(buf, sizeof(buf));
	p = buf;
	len = sizeof(buf);

	writen(ifd, "\x0d", 1);

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));
		login_timeout.tv_sec = SSH_INPUT_TIMEOUT;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Catch a signal from child process */
			if (errno == EINTR)
			{
				return -1;
			}

			return -1;
		}
		else if (ret == 0)
		{
			/* Maybe input successed */
			if (response == 1)
			{
				if (is_echo == 2)
				{
					//get_passwd_return_value(buf, sizeof(buf) - len);
				}
				break;
			}
			/* This is not a shell */
			else
			{
				fprintf(stderr, "No response of ENTER, exit.\n");
				return -1;
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			n = read(ofd, p, len);

			if (n == 0 && strcmp(string, "exit") != 0)
			{
				return -1;
			}
			else if (n == 0 && strcmp(string, "exit") == 0)
			{
				return 0;
			}
			else
			{
				writen(2, p, n);
			}

			p = p + n;
			len = len - n;
		}

	}

	return 0;
}

	int
try_login_target(int cid, int ofd, int efd)
{
	fd_set rfds, rtmp;
	int nfd, ret, n, round = 0, response = 0;
	struct timeval login_timeout;
	char buf[1024];

	FD_ZERO(&rfds);
	FD_SET(ofd, &rfds);
	FD_SET(efd, &rfds);
	nfd = (ofd > efd ? ofd : efd) + 1;
	int ok = 0;

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));

		if (!round || ok == 0)
		{
			login_timeout.tv_sec = SSH_LOGIN_TIMEOUT;
			login_timeout.tv_usec = 0;
		}
		else
		{
			login_timeout.tv_sec = SSH_INPUT_TIMEOUT;
			login_timeout.tv_usec = 0;
		}

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Cacth child exit process */
			if (errno == EINTR)
			{
				return -1;
			}

			return -1;
		}
		/* Time out */
		else if (ret == 0)
		{
			/* Maybe login successed */
			if (response == 1 && ok == 1)
			{
				return 0;
			}
			/* Login failed */
			else
			{
				return -1;
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			bzero(buf, sizeof(buf));
			n = read(ofd, buf, sizeof(buf));
			if (strchr(buf, ':') != NULL)
				ok = 1;

			/* Pipe is closed */
			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(2, buf, n);
			}
		}

		/* Recv message from stderr */
		if (FD_ISSET(efd, &rtmp))
		{
			bzero(buf, sizeof(buf));
			n = read(efd, buf, sizeof(buf));

			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(2, buf, n);
			}

			fprintf(stderr, "Login error. Recv stderr message.\n");
			return -1;
		}

		round++;
	}

	return -1;
}

int
dail_test(CANDIDATE *c)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt, protocol, su_flag = 1;
	char ssh_binary[128];

	/* Create stdin pipe fd */
	if (pipe(i_des) == -1)
	{
		perror("pipe");
		//write_log("Can't create the IPC pipe");
		return -1;
	}
	/* Create stdout pipe fd */
	if (pipe(o_des) == -1)
	{
		perror("pipe");
		//write_log("Can't create the IPC pipe");
		return -1;
	}
	/* Create stderr pipe fd */
	if (pipe(e_des) == -1)
	{
		perror("pipe");
		//write_log("Can't create stderr pipe.");
		return -1;
	}

	pid = fork();

	if (pid == -1)
	{
		//write_log("Can't create new process.");
		return -1;
	}
	/* Child process */
	else if (pid == 0)
	{
		//close(lock_fd);

		dup2(i_des[0], STDIN_FILENO);
		dup2(o_des[1], STDOUT_FILENO);
		dup2(e_des[1], STDERR_FILENO);

		close(i_des[0]);
		close(i_des[1]);

		close(o_des[0]);
		close(o_des[1]);

		close(e_des[0]);
		close(e_des[1]);

		bzero(ssh_binary, sizeof(ssh_binary));
		snprintf(ssh_binary, sizeof(ssh_binary), "%s/autossh", BINARY_PATH);

		if (c->login_method != 5)
		{
			if (execv(ssh_binary, c->av) == -1)
				// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288",
				// "-zfreesvr", "-tt", (char*)0 ) == -1 )
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else if (c->login_method == 5)
		{
			if (execvp("telnet", c->av) == -1)
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}

		return 0;
	}
	/* Parent process */
	else
	{
		close(i_des[0]);
		close(o_des[1]);
		close(e_des[1]);

		/* Set proc name */
		/*protocol = m->next->servinfo->protocol;
		  sip = m->next->servinfo->device_serverip;
		  set_proc_title("[%s] %s->%s <%s>", PROGRAM_NAME, pname[protocol], sip, timestamp());
		 */
		cnt = 0;

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			//write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			//insert_log_failed(m->next);
			close(i_des[1]);
			close(o_des[0]);
			close(e_des[0]);
			return -1;
		}

		if (c->login_method ==5)
		{
			ret = try_input_string(pid, i_des[1], o_des[0], c->username, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				//write_log("\nUPDATE MYSQL");
				//update_mysql(mp->servinfo, 0);
				//insert_log_failed(mp->next);
				close(i_des[1]);
				close(o_des[0]);
				close(e_des[0]);
				return -1;

			}

			ret = try_input_string(pid, i_des[1], o_des[0], c->cur_password, 0);
			if (ret == -1)
			{                                
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL); 
				//write_log("\nUPDATE MYSQL");
				//update_mysql(mp->servinfo, 0); 
				//insert_log_failed(mp->next);
				close(i_des[1]);
				close(o_des[0]);
				close(e_des[0]);
				return -1;

			}
		}


		if (try_input_string(pid, i_des[1], o_des[0], "exit", 1) == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			close(i_des[1]);
			close(o_des[0]);
			close(e_des[0]);
			return -1;
		}

	}

	close(i_des[1]);
	close(o_des[0]);
	close(e_des[0]);
	return 0;
}

int
init_log(void)
{
	char logfile[] = "/opt/freesvr/audit/dial/log/freesvr_dial.log";

	if (logfile && strcasecmp(logfile, "stderr"))
	{
		int tmpfd;
		tmpfd = open(logfile, O_APPEND | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
		if (tmpfd == -1 || dup2(tmpfd, 2) == -1)
		{
			fprintf(stderr, "Unable to open logfile %s\n", logfile);
			return (-1);
		}
		else
			return (0);
	}
	return (-1);
}

int
fetch_aes_key(MYSQL *sql_conn)
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    char buf[128];
    int ret = 0;

    bzero(buf, sizeof(buf));
    bzero(aes_key, sizeof(aes_key));
    snprintf(buf, sizeof(buf),
        "select udf_decrypt(svalue) from setting where sid=32");

    if (mysql_query(sql_conn, buf) == 1)
    {
        fprintf(stderr, "Query to mysql Error, Exit.\n");
        return -1;
    }

    res = mysql_store_result(sql_conn);

    row = mysql_fetch_row(res);

    if (row && row[0])
        strncpy(aes_key, row[0], sizeof(aes_key));

    mysql_free_result(res);

    return ret;
}

int
main(int argc, char *argv[])
{
	MYSQL *sql_conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	char buf[1024];
	CANDIDATE candidate;
	int server_group_id = 0;
	char device_ids[1024] = {0};

	init_log();
	sql_conn = mysql_init(NULL);
	sql_conn =
		mysql_real_connect(sql_conn, "127.0.0.1", "freesvr", "freesvr", "audit_sec", 0, NULL, 0);

    fetch_aes_key(sql_conn);

	extern int opterr, optind, optopt;
	extern char *optarg;
	int option;
	opterr = 0;

	while ((option = getopt(argc, argv, "g:i:")) != -1)
	{
		switch (option)
		{
			case ('g'):
				server_group_id = atoi(optarg);
				break;
			case ('i'):
				server_group_id = 0;
				strcpy(device_ids, optarg);
				break;
			default:
				break;
		}
	}

	if (server_group_id != 0)
	{	
		snprintf(buf, sizeof(buf), "SELECT id,username,device_ip,port,login_method,"\
				"aes_decrypt(cur_password, '%s'),aes_decrypt(old_password, '%s'),aes_decrypt(new_password, '%s') "\
				"FROM devices where device_ip in (SELECT device_ip FROM servers WHERE groupid=%d)", aes_key, aes_key, aes_key, server_group_id);
	}
	else if (device_ids[0] != 0)
	{
		snprintf(buf, sizeof(buf), "SELECT id,username,device_ip,port,login_method,"\
                "aes_decrypt(cur_password, '%s'),aes_decrypt(old_password, '%s'),aes_decrypt(new_password, '%s') "\
				"FROM devices where id in (%s)", aes_key, aes_key, aes_key, device_ids);
	}
	else
	{
		snprintf(buf, sizeof(buf), "SELECT id,username,device_ip,port,login_method,"\
                "aes_decrypt(cur_password, '%s'),aes_decrypt(old_password, '%s'),aes_decrypt(new_password, '%s') "\
				"FROM devices", aes_key, aes_key, aes_key);
	}

	if (mysql_query(sql_conn, buf) != 0)
	{
		printf("%s\n", mysql_error(sql_conn));
		return -1;
	}

	if ((res = mysql_store_result(sql_conn)) == NULL)
	{
		printf("%s\n", mysql_error(sql_conn));
		return -1;
	}
	
	int ret;
	while ((row = mysql_fetch_row(res)) != NULL)
	{
		memset(&candidate, 0x00, sizeof(candidate));
		candidate.id = atoi(row[0]);
		strcpy(candidate.username, row[1]);
		strcpy(candidate.ipaddr, row[2]);
		candidate.port = atoi(row[3]);
		candidate.login_method = atoi(row[4]);
		if (row[5] == NULL) continue;
		strcpy(candidate.cur_password, row[5]);
		if (row[6] != NULL)
		strcpy(candidate.old_password, row[6]);
		if (row[7] != NULL)
			strcpy(candidate.new_password, row[7]);
		candidate.av = execv_argument_create(candidate.ipaddr, candidate.username, candidate.cur_password, candidate.login_method, candidate.port);
		if (candidate.login_method != 3 && candidate.login_method != 5)
			continue;
		ret = dail_test(&candidate);
		printf("%s\t%s@%s:%d %s ", candidate.login_method == 5 ? "telnet" : "ssh", candidate.username, candidate.ipaddr, candidate.port, candidate.cur_password);
		printf("id=%d, result=%s\n", candidate.id, ret == 0 ? "success" : "failed");
	}

	mysql_free_result(res);
	return 0;
}

