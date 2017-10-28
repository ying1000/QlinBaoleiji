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

#define LOGIN_TIMEOUT 5
#define INPUT_TIMEOUT 2
#define SSH1          1
#define SSH2          2
#define TELNET        3

#define BINARY_PATH "/home/zhangzhong/passwd/v0.1/src"

typedef struct _command
{
	struct _command *next;
	char *string;
	int echo;
} Command;

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
try_input_string(int cid, int ifd, int ofd, const char *string, int is_echo, int is_record)
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
		login_timeout.tv_sec = INPUT_TIMEOUT;
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
		login_timeout.tv_sec = INPUT_TIMEOUT;
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

	if (is_record)
	{
		FILE *fp = fopen("record_screen", "w");
		fprintf(fp, "%s", buf);
		fclose(fp);
	}
	// printf("execute successed.\n");
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
			login_timeout.tv_sec = LOGIN_TIMEOUT;
			login_timeout.tv_usec = 0;
		}
		else
		{
			login_timeout.tv_sec = INPUT_TIMEOUT;
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
ssh_modify_password(int protocol, char *ssh_argv[], struct _command *c)
{
	int i_des[2], o_des[2], e_des[2];
	int pid, ret, cnt;
	char ssh_binary[128], *sip;
	Command *cp = c->next;

	/* Create stdin pipe fd */
	if (pipe(i_des) == -1)
	{
		fprintf(stderr, "Can't create the IPC pipe");
		return -1;
	}

	/* Create stdout pipe fd */
	if (pipe(o_des) == -1)
	{
		fprintf(stderr, "Can't create the IPC pipe");
		return -1;
	}

	/* Create stderr pipe fd */
	if (pipe(e_des) == -1)
	{
		fprintf(stderr, "Can't create stderr pipe.");
		return -1;
	}

	pid = fork();

	if (pid == -1)
	{
		fprintf(stderr, "Can't create new process.");
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

		if (protocol != TELNET)
		{
			if (execv(ssh_binary, ssh_argv) == -1)
			{
				perror("In child process, can't execute ssh command.");
				return -1;
			}
		}
		else
		{
			if (execvp("telnet", ssh_argv) == -1)
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

		if (try_login_target(pid, o_des[0], e_des[0]) == -1)
		{
			fprintf(stderr, "Can't login target.\n");
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			return -1;
		}

		while (cp)
		{
			ret = try_input_string(pid, i_des[1], o_des[0], cp->string, cp->echo, 1);

			if (ret == -1)
			{
				kill_child_process(pid, 9);
				wait_child_process(pid, NULL);
				return -1;
			}

			cp = cp->next;
		}

		if (try_input_string(pid, i_des[1], o_des[0], "exit", 1, 0) == -1)
		{
			kill_child_process(pid, 9);
			wait_child_process(pid, NULL);
			return -1;
		}

	}

	return 0;
}

Command *
command_list_create(char **cmd, int *echo)
{
	Command *root, *p, *c;
	int i, len;

	root = (Command *) malloc(sizeof(Command));

	if (root == NULL)
	{
		fprintf(stderr, "Malloc failed.\n");
		return NULL;
	}
	else
	{
		memset(root, 0x00, sizeof(Command));
	}

	p = root;

	for (i = 0; cmd[i] != NULL; i++)
	{
		c = (Command *) malloc(sizeof(Command));

		if (c == NULL)
		{
			fprintf(stderr, "Malloc failed.\n");
			command_list_destroy(root);
			return NULL;
		}
		else
		{
			memset(c, 0x00, sizeof(Command));
		}

		len = strlen(cmd[i]) + 1;
		c->string = (char *) malloc(len);

		if (c->string == NULL)
		{
			fprintf(stderr, "Malloc failed.\n");
			command_list_destroy(root);
			return NULL;
		}
		else
		{
			memset(c->string, 0x00, len);
		}

		strcpy(c->string, cmd[i]);
		c->echo = echo[i];

		p->next = c;
		p = c;
	}

	return root;
}

int
command_list_destroy(Command * root)
{
	Command *p = root, *q;

	while (p)
	{
		q = p;
		p = p->next;

		if (q->string)
			free(q->string);

		free(q);
	}

	return 0;
}

int
main(int argc, char *av[])
{
	char *argv[] =
		{ "autossh", "-tt", "222.35.62.134", "-l", "zg", "-p", "2288", "-z", "freesvr",
 (char *) 0 };
	char *cmd[] = { "cat /proc/cpuinfo", (char *) 0 };
	int echo[] = { 1, 1, 1 };

	Command *p;
	p = command_list_create(cmd, echo);

	if (p == NULL)
	{
		fprintf(stderr, "Create command list failed.\n");
		return -1;
	}

	ssh_modify_password(2, argv, p);

	command_list_destroy(p);

	return 0;
}
