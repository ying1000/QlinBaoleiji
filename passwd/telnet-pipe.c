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
#include "list.h"
#include "log.h"
#include "mysql.h"

#define SSH_LOGIN_TIMEOUT 5
#define SSH_INPUT_TIMEOUT 1

static int
insert_log_failed(const Modify_info * minfo)
{
	MYSQL *sql;
	char buf[2048];
	int ret = 0;
	Modify_info *mp;
	Info *info;

	sql = mysql_init(NULL);
	sql =
		mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
						   config.mysql_database, 0, NULL, 0);

	if (sql == NULL)
		return -1;

	write_log("Insert Login failed into log table.");
	mp = (Modify_info *) minfo;

	while (mp)
	{
		info = mp->servinfo;
		bzero(buf, sizeof(buf));
		snprintf(buf, sizeof(buf),
				 "INSERT INTO log (time,device_ip,username,update_success_flag) VALUES(now(),\"%s\",\"%s\",\"%s\")",
				 info->device_serverip, info->device_username, "No");

		write_log("sql_query:%s", buf);

		if (mysql_query(sql, buf) != 0)
		{
			write_log("Insert MySQL log table failed.");
			ret = -1;
		}

		mp = mp->next;
	}

	mysql_close(sql);
	return ret;
}
static int
update_mysql(const Info * info, int res)
{
	MYSQL *sql;
	char buf[2048], tmp[32];
	List_head *p;
	int ret = 0;

	sql = mysql_init(NULL);
	sql =
		mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
						   config.mysql_database, 0, NULL, 0);

	if (sql == NULL)
		return -1;

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf),
			 "INSERT INTO log (time,device_ip,username,update_success_flag) VALUES(now(),\"%s\",\"%s\",\"%s\")",
			 info->device_serverip, info->device_username, res ? "Yes" : "No");

	write_log("%s", buf);
	if (mysql_query(sql, buf) != 0)
	{
		write_log("Insert MySQL log table failed.");
		ret = -1;
	}

	if (res == 1)
	{
		bzero(buf, sizeof(buf));
		snprintf(buf, sizeof(buf),
				 "UPDATE devices SET automodify=1,old_password=\"%s\",cur_password=\"%s\",last_update_time=now() WHERE ",
				 info->device_password, info->modify_password);
		p = info->id_list;

		while (p->next)
		{
			p = p->next;
			bzero(tmp, sizeof(tmp));
			snprintf(tmp, sizeof(tmp), "id=%d OR ", p->element);
			strcat(buf, tmp);
		}

		buf[strlen(buf) - 4] = 0x00;

		write_log("%s", buf);
		if (mysql_query(sql, buf) != 0)
		{
			write_log("Update MySQL devices table failed.");
			ret = -1;
		}
	}

	mysql_close(sql);
	return ret;
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
get_passwd_return_value(const char *s, int len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		printf("%02x ", (unsigned char) s[i]);
	}
	printf("\n");
	return 0;
}

int
try_input_string(int cid, int ifd, int ofd, const char *string, int is_echo)
{
	fd_set rfds, rtmp;
	int nfd, ret, n, response = 0, len;
	struct timeval login_timeout;
	char buf[1024], *p;

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
					if (strcasecmp(buf, string) == 0)
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
					get_passwd_return_value(buf, sizeof(buf) - len);
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

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));

		if (!round)
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
			if (response == 1)
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
ssh_modify_password(Modify_info * m)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret;
	char ssh_binary[128];
	Modify_info *mp = m;
	Command *cp;

	/* Create stdin pipe fd */
	if (pipe(i_des) == -1)
	{
		write_log("Can't create the IPC pipe");
		return -1;
	}
	/* Create stdout pipe fd */
	if (pipe(o_des) == -1)
	{
		write_log("Can't create the IPC pipe");
		return -1;
	}
	/* Create stderr pipe fd */
	if (pipe(e_des) == -1)
	{
		write_log("Can't create stderr pipe.");
		return -1;
	}

	pid = fork();

	if (pid == -1)
	{
		write_log("Can't create new process.");
		return -1;
	}
	/* Child process */
	else if (pid == 0)
	{
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

		// char ** av = m->next->servinfo->argv;
		// write_log( "%s %s %s %s %s %s %s", av[0], av[1], av[2], av[3], av[4], av[5], av[6] );
		if (execv(ssh_binary, m->next->servinfo->argv) == -1)
			// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288", "-zfreesvr",
			// "-tt", (char*)0 ) == -1 )
		{
			perror("In child process, can't execute ssh command.");
			return -1;
		}

		return 0;
	}
	/* Parent process */
	else
	{
		close(i_des[0]);
		close(o_des[1]);
		close(e_des[1]);

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			insert_log_failed(m->next);
			return -1;
		}

		while (mp->next)
		{
			mp = mp->next;
			cp = mp->servinfo->input;

			while (cp->execution)
			{
				ret = try_input_string(pid, i_des[1], o_des[0], cp->string, cp->echo);

				if (ret == -1)
				{
					kill_child_process(pid, 9);
					wait_child_process(pid, NULL);
					write_log("\nUPDATE MYSQL");
					update_mysql(mp->servinfo, 0);
					insert_log_failed(mp->next);
					return -1;
				}

				cp = cp->next;
			}

			write_log("\nUPDATE MYSQL");
			update_mysql(mp->servinfo, 1);
		}

		try_input_string(pid, i_des[1], o_des[0], "exit", 1);

	}

	return 0;
}
