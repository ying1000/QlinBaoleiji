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
#include "list.h"
#include "log.h"
#include "mysql.h"

#define SSH_LOGIN_TIMEOUT config.timeout
#define SSH_INPUT_TIMEOUT 3

static char *pname[] = { "AGENT", "SSH1", "SSH2", "TELNET" };
char *fetch_su_password(const char *device_ip);
char *shift_old_password(const char *old_password);

static char *
timestamp(void)
{
	static char tstr[32];
	struct tm *tm;
	const char *fmt = "%Y.%m.%d-%H:%M:%S";

	struct timeval tv;
	gettimeofday(&tv, NULL);

	time_t caltime = tv.tv_sec;

	memset(tstr, 0x00, sizeof(tstr));

	if ((tm = localtime(&caltime)) == NULL)
		return (NULL);

	if (strftime(tstr, sizeof(tstr) - 1, fmt, tm) == 0)
		return (NULL);

	return (tstr);
}

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

		// write_log( "sql_query:%s", buf );

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

int
update_mysql(const Info * info, int res)
{
	MYSQL *sql;
	char buf[2048], tmp[32], *sp;
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

	// write_log( "%s", buf );
	if (mysql_query(sql, buf) != 0)
	{
		write_log("Insert MySQL log table failed.");
		ret = -1;
	}

	if (res == 1)
	{
		bzero(buf, sizeof(buf));

        if (config.udf) {
            snprintf(buf, sizeof(buf),
                "UPDATE devices SET automodify=1,old_password=udf_encrypt(\"%s\"),cur_password=udf_encrypt(\"%s\"),last_update_time=now() WHERE ",
                (sp = shift_old_password(info->device_password)), info->modify_password);
        } else {
            snprintf(buf, sizeof(buf),
                "UPDATE devices SET automodify=1,old_password=aes_encrypt(\"%s\", \"%s\"),cur_password=aes_encrypt(\"%s\", \"%s\"),last_update_time=now() WHERE ",
                (sp = shift_old_password(info->device_password)), aes_key, info->modify_password, aes_key);
        }

		free(sp);
		p = info->id_list;

		while (p->next)
		{
			p = p->next;
			bzero(tmp, sizeof(tmp));
			snprintf(tmp, sizeof(tmp), "id=%d OR ", p->element);
			strcat(buf, tmp);
		}

		buf[strlen(buf) - 4] = 0x00;

		// write_log( "%s", buf );
		if (mysql_query(sql, buf) != 0)
		{
			write_log("Update MySQL devices table failed.");
			ret = -1;
		}

		bzero(buf, sizeof(buf));
		snprintf(buf, sizeof(buf),
				 "INSERT INTO password_cache (generate_time,password_hash) VALUES(NOW(),MD5('%s'))",
				 info->modify_password);

		if (mysql_query(sql, buf) != 0)
		{
			write_log("[%s]: Insert password_cache table failed.", __func__);
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

	if (is_echo == 3 && strcasestr(buf, "Changing password")) {
		return 1;
	}

	return 0;
}

int
try_login_target(int cid, int ofd, int efd)
{
	fd_set rfds, rtmp;
	int nfd, ret, n, round = 0, response = 0;
	struct timeval login_timeout;
	char buf[10240];

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

			//fprintf(stderr, "Login error. Recv stderr message.\n");
			//return -1;
		}

		round++;
	}

	return -1;
}

int
ssh_modify_password(Modify_info * m)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt, protocol, su_flag = 1;
	char ssh_binary[128], *sip, *su_password;
	Modify_info *mp = m;
	Command *cp;

	char **av = m->next->servinfo->argv;
	write_log("[%s] %s %s %s %s %s %s %s", __func__, av[0], av[1], av[2], av[3], av[4], av[5], av[6]);

	/* Create stdin pipe fd */
	if (pipe(i_des) == -1)
	{
		perror("pipe");
		write_log("Can't create the IPC pipe");
		return -1;
	}
	/* Create stdout pipe fd */
	if (pipe(o_des) == -1)
	{
		perror("pipe");
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
		close(lock_fd);

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

		if (m->next->servinfo->protocol == SSH1_PROTOCOL
				|| m->next->servinfo->protocol == SSH2_PROTOCOL)
		{
			if (execv(ssh_binary, m->next->servinfo->argv) == -1)
				// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288",
				// "-zfreesvr", "-tt", (char*)0 ) == -1 )
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			if (execvp("telnet", m->next->servinfo->argv) == -1)
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
		protocol = m->next->servinfo->protocol;
		sip = m->next->servinfo->device_serverip;
		set_proc_title("[%s] %s->%s <%s>", PROGRAM_NAME, pname[protocol], sip, timestamp());

		cnt = 0;

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			insert_log_failed(m->next);
			close(i_des[1]);
			close(o_des[0]);
			close(e_des[0]);
			return -1;
		}

		while (mp->next)
		{
			mp = mp->next;
			cp = mp->servinfo->input;

			while (cp->execution == TELNET_PROTOCOL && cnt == 0)
			{
				ret = try_input_string(pid, i_des[1], o_des[0], cp->string, cp->echo);

				if (ret == -1)
				{
					kill_child_process(pid, 9);
					wait_child_process(pid, NULL);
					write_log("\nUPDATE MYSQL");
					update_mysql(mp->servinfo, 0);
					insert_log_failed(mp->next);
					close(i_des[1]);
					close(o_des[0]);
					close(e_des[0]);
					return -1;
				}

				cp = cp->next;
			}

			if (su_flag == 1)
			{
				su_flag = 0;
				su_password = fetch_su_password(mp->servinfo->device_serverip);
				if (su_password != NULL)
				{
					su_flag = 2;
					ret = try_input_string(pid, i_des[1], o_des[0], "su -", 1);
					if (ret == -1)
					{
						kill_child_process(pid, 9);
						wait_child_process(pid, NULL);
						write_log("\nUPDATE MYSQL");
						update_mysql(m->next->servinfo, 0);
						insert_log_failed(m->next);
						close(i_des[1]);
						close(o_des[0]);
						close(e_des[0]);
						return -1;
					}
					ret = try_input_string(pid, i_des[1], o_des[0], su_password, 0);
					if (ret == -1)
					{
						kill_child_process(pid, 9);
						wait_child_process(pid, NULL);
						write_log("\nUPDATE MYSQL");
						update_mysql(m->next->servinfo, 0);
						insert_log_failed(m->next);
						close(i_des[1]);
						close(o_des[0]);
						close(e_des[0]);
						return -1;
					}
				}
			}

			while (cp->execution)
			{
				if (cp->execution == TELNET_PROTOCOL && cnt > 0)
				{
					cp = cp->next;
					continue;
				}

				ret = try_input_string(pid, i_des[1], o_des[0], cp->string, cp->echo);

				if (ret == -1)
				{
					kill_child_process(pid, 9);
					wait_child_process(pid, NULL);
					write_log("\nUPDATE MYSQL");
					update_mysql(mp->servinfo, 0);
					insert_log_failed(mp->next);
					close(i_des[1]);
					close(o_des[0]);
					close(e_des[0]);
					return -1;
				}
				else if (ret == 1) {
					cp = cp->next;
				}

				cp = cp->next;
			}

			write_log("\nUPDATE MYSQL");
			update_mysql(mp->servinfo, 1);
			cnt++;
		}

		if (su_flag == 2)
		{
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
modify_password_on_huawei_device(Modify_info * m)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt, protocol;
	char ssh_binary[128], *sip, cmd_buf[256];
	Modify_info *mp = m;
	Command *cp;

	char **av = m->next->servinfo->argv;
	write_log("%s %s %s %s %s %s %s", av[0], av[1], av[2], av[3], av[4], av[5], av[6]);

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
		close(lock_fd);

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

		if (m->next->servinfo->protocol == SSH1_PROTOCOL
			|| m->next->servinfo->protocol == SSH2_PROTOCOL)
		{
			if (execv(ssh_binary, m->next->servinfo->argv) == -1)
				// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288",
				// "-zfreesvr", "-tt", (char*)0 ) == -1 )
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			//if (execvp("telnet", m->next->servinfo->argv) == -1)
			if (execlp("telnet", "telnet", m->next->servinfo->device_serverip, NULL) == -1)
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
		protocol = m->next->servinfo->protocol;
		sip = m->next->servinfo->device_serverip;
		set_proc_title("[%s] %s->%s <%s>", PROGRAM_NAME, pname[protocol], sip, timestamp());

		cnt = 0;

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			insert_log_failed(m->next);
			return -1;
		}

		// Input telnet password to login huawei device
		if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_username, 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_password, 0);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}
		}

		// Input system
		ret = try_input_string(pid, i_des[1], o_des[0], "system", 1);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		// Input aaa
		ret = try_input_string(pid, i_des[1], o_des[0], "aaa", 1);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		while (mp->next)
		{
			mp = mp->next;
			snprintf(cmd_buf, sizeof(cmd_buf), "local-user %s password cipher %s",
					 mp->servinfo->device_username, mp->servinfo->modify_password);
			ret = try_input_string(pid, i_des[1], o_des[0], cmd_buf, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			write_log("\nUPDATE MYSQL");
			update_mysql(mp->servinfo, 1);
		}

		// Input quit
		ret = try_input_string(pid, i_des[1], o_des[0], "quit", 1);
		ret = try_input_string(pid, i_des[1], o_des[0], "quit", 1);
		ret = try_input_string(pid, i_des[1], o_des[0], "save", 1);
		ret = try_input_string(pid, i_des[1], o_des[0], "y", 1);

		if (try_input_string(pid, i_des[1], o_des[0], "quit", 1) == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			return -1;
		}

	}

	return 0;
}

int
modify_password_on_h3c_device(Modify_info * m)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt, protocol;
	char ssh_binary[128], *sip, cmd_buf[256];
	Modify_info *mp = m;
	Command *cp;

	char **av = m->next->servinfo->argv;
	write_log("%s %s %s %s %s %s %s", av[0], av[1], av[2], av[3], av[4], av[5], av[6]);

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
		close(lock_fd);

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

		if (m->next->servinfo->protocol == SSH1_PROTOCOL
			|| m->next->servinfo->protocol == SSH2_PROTOCOL)
		{
			if (execv(ssh_binary, m->next->servinfo->argv) == -1)
				// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288",
				// "-zfreesvr", "-tt", (char*)0 ) == -1 )
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			//if (execvp("telnet", m->next->servinfo->argv) == -1)
			
			if (execlp("telnet", "telnet", m->next->servinfo->device_serverip, NULL) == -1)
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
		protocol = m->next->servinfo->protocol;
		sip = m->next->servinfo->device_serverip;
		set_proc_title("[%s] %s->%s <%s>", PROGRAM_NAME, pname[protocol], sip, timestamp());

		cnt = 0;

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			insert_log_failed(m->next);
			return -1;
		}

		// Input telnet password to login h3c device
		if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_username, 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_password, 0);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}
		}

		// Input system
		ret = try_input_string(pid, i_des[1], o_des[0], "system", 1);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		while (mp->next)
		{
			mp = mp->next;
			snprintf(cmd_buf, sizeof(cmd_buf), "local-user %s", mp->servinfo->device_username);
			ret = try_input_string(pid, i_des[1], o_des[0], cmd_buf, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			snprintf(cmd_buf, sizeof(cmd_buf), "password cipher %s", mp->servinfo->modify_password);
			ret = try_input_string(pid, i_des[1], o_des[0], cmd_buf, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], "save", 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], "y", 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], "", 0);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], "quit", 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			write_log("\nUPDATE MYSQL");
			update_mysql(mp->servinfo, 1);
		}

		// Input quit
		ret = try_input_string(pid, i_des[1], o_des[0], "quit", 1);

		if (try_input_string(pid, i_des[1], o_des[0], "quit", 1) == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			return -1;
		}

	}

	return 0;
}

char *
fetch_superpassword(const char *device_ip)
{
	MYSQL *sql_conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	char buf[256];
	static char ret[64];

	// fprintf(stderr, "%s\n", __func__);
	sql_conn = mysql_init(NULL);
	sql_conn =
		mysql_real_connect(sql_conn, "127.0.0.1", "freesvr", "freesvr", "audit_sec", 0, NULL, 0);

	// if (sql_conn == NULL) fprintf(stderr, "connect error.\n");

    if (config.udf) {
        snprintf(buf, sizeof(buf),
            "SELECT udf_decrypt(superpassword) FROM servers WHERE device_ip='%s'", device_ip);
    } else {
        snprintf(buf, sizeof(buf),
            "SELECT aes_decrypt(superpassword, \"%s\") FROM servers WHERE device_ip='%s'", aes_key, device_ip);
    }

	if (mysql_query(sql_conn, buf) != 0)
		fprintf(stderr, "mysql: %s\n", mysql_error(sql_conn));

	res = mysql_store_result(sql_conn);
	row = mysql_fetch_row(res);

	if (row && row[0])
		strncpy(ret, row[0], sizeof(ret) - 1);

	mysql_free_result(res);
	mysql_close(sql_conn);
	return ret;
}

char *
fetch_su_password(const char *device_ip)
{
	MYSQL *sql_conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	char buf[256];
	static char ret[128];

	// fprintf(stderr, "%s\n", __func__);
    bzero(ret, sizeof(ret));
	sql_conn = mysql_init(NULL);
	sql_conn =
		mysql_real_connect(sql_conn, "127.0.0.1", "freesvr", "freesvr", "audit_sec", 0, NULL, 0);

	// if (sql_conn == NULL) fprintf(stderr, "connect error.\n");

    if (config.udf) {
        snprintf(buf, sizeof(buf),
            "select udf_decrypt(superpassword) from servers where device_ip in (select device_ip from devices where device_ip=\"%s\" AND su_passwd=1)", device_ip);
    } else {
        snprintf(buf, sizeof(buf),
            "select aes_decrypt(superpassword, \"%s\") from servers where device_ip in (select device_ip from devices where device_ip=\"%s\" AND su_passwd=1)", aes_key, device_ip);
    }

    if (mysql_query(sql_conn, buf) != 0)
		fprintf(stderr, "mysql: %s\n", mysql_error(sql_conn));

	res = mysql_store_result(sql_conn);
	row = mysql_fetch_row(res);

	if (row && row[0])
		strncpy(ret, row[0], sizeof(ret) - 1);

	mysql_free_result(res);
	mysql_close(sql_conn);

    if (ret[0] == 0x00)
        return NULL;
    else
	    return ret;
}

int
modify_password_on_cisco_device(Modify_info * m)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt, protocol;
	char ssh_binary[128], *sip, cmd_buf[256];
	Modify_info *mp = m;
	Command *cp;

	char **av = m->next->servinfo->argv;
	write_log("%s %s %s %s %s %s %s", av[0], av[1], av[2], av[3], av[4], av[5], av[6]);

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
		close(lock_fd);

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

		if (m->next->servinfo->protocol == SSH1_PROTOCOL
			|| m->next->servinfo->protocol == SSH2_PROTOCOL)
		{
			if (execv(ssh_binary, m->next->servinfo->argv) == -1)
				// if( execl( ssh_binary, "autossh", "monitor@222.35.62.170", "-p2288",
				// "-zfreesvr", "-tt", (char*)0 ) == -1 )
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			//if (execvp("telnet", m->next->servinfo->argv) == -1)
			
			if (execlp("telnet", "telnet", m->next->servinfo->device_serverip, NULL) == -1)
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
		protocol = m->next->servinfo->protocol;
		sip = m->next->servinfo->device_serverip;
		set_proc_title("[%s] %s->%s <%s>", PROGRAM_NAME, pname[protocol], sip, timestamp());

		cnt = 0;

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			write_log("Can't login target.");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			insert_log_failed(m->next);
			return -1;
		}

		// Input telnet password to login cisco device
		if (m->next->servinfo->protocol == TELNET_PROTOCOL)
		{
			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_username, 1);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}

			ret = try_input_string(pid, i_des[1], o_des[0], m->next->servinfo->master_password, 0);
			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(m->next->servinfo, 0);
				insert_log_failed(m->next);
				return -1;
			}
		}

		// Input enable
		ret = try_input_string(pid, i_des[1], o_des[0], "enable", 1);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		// fprintf(stderr, "superpassword is %s\n",
		// fetch_superpassword(m->next->servinfo->device_serverip));
		// ret = try_input_string(pid, i_des[1], o_des[0], "nwnet-link", 0);
		ret =
			try_input_string(pid, i_des[1], o_des[0],
							 fetch_superpassword(m->next->servinfo->device_serverip), 0);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		// Input conf t
		ret = try_input_string(pid, i_des[1], o_des[0], "conf t", 1);
		if (ret == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			write_log("\nUPDATE MYSQL");
			update_mysql(m->next->servinfo, 0);
			insert_log_failed(m->next);
			return -1;
		}

		while (mp->next)
		{
			mp = mp->next;
			snprintf(cmd_buf, sizeof(cmd_buf), "username %s password %s",
					 mp->servinfo->device_username, mp->servinfo->modify_password);
			ret = try_input_string(pid, i_des[1], o_des[0], cmd_buf, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				write_log("\nUPDATE MYSQL");
				update_mysql(mp->servinfo, 0);
				insert_log_failed(mp->next);
				return -1;
			}

			write_log("\nUPDATE MYSQL");
			update_mysql(mp->servinfo, 1);
		}

		// Input wr
		ret = try_input_string(pid, i_des[1], o_des[0], "end", 1);
		ret = try_input_string(pid, i_des[1], o_des[0], "wr", 1);

		if (try_input_string(pid, i_des[1], o_des[0], "quit", 1) == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			return -1;
		}

	}

	return 0;
}
