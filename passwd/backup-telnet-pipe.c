#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

//int judge_login( int, int, int );

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
telnet_modify_password(char *telnet_argv[])
{
	int i_des[2], o_des[2], e_des[2];
	int pid, n, nfd, ret;
	char buf[1024];
	fd_set rfds;
	struct timeval timeout;

	bzero(buf, 1024);

	/* Create stdin pipe fd */
	if (pipe(i_des) == -1)
	{
		perror("Can't create the IPC pipe");
		return -1;
	}
	/* Create stdout pipe fd */
	if (pipe(o_des) == -1)
	{
		perror("Can't create the IPC pipe");
		return -1;
	}
	/* Create stderr pipe fd */
	if (pipe(e_des) == -1)
	{
		perror("Can't create stderr pipe.");
		return -1;
	}

	pid = fork();

	if (pid == -1)
	{
		perror("Can't create new process.");
		return 1;
	}
	/* Child process */
	else if (pid == 0)
	{
		dup2(i_des[1], STDOUT_FILENO);
		dup2(o_des[0], STDIN_FILENO);
		dup2(e_des[1], STDERR_FILENO);

		close(i_des[0]);
		close(i_des[1]);

		close(o_des[0]);
		close(o_des[1]);

		close(e_des[0]);
		close(e_des[1]);

		if (execvp("telnet", telnet_argv) == -1)
		{
			perror("In child process, can't execute telnet command.");
			return -1;
		}

		return 0;
	}
	/* Parent process */
	else
	{
		close(i_des[1]);
		close(o_des[0]);
		close(e_des[1]);

		ret = try_telnet_login(pid, o_des[1], i_des[0], e_des[0]);
		printf("ret = %d\n", ret);
		ret = try_execute_command(pid, o_des[1], i_des[0], "echo hello", 1);
		printf("ret = %d\n", ret);
		/* ret = try_execute_command( pid, o_des[1], i_des[0], "freesvr", 0 ); printf( "ret =
		   %d\n", ret ); ret = try_execute_command( pid, o_des[1], i_des[0], "hefei!@#", 0 );
		   printf( "ret = %d\n", ret ); ret = try_execute_command( pid, o_des[1], i_des[0],
		   "hefei!@#", 0 ); printf( "ret = %d\n", ret ); */
		ret = try_execute_command(pid, o_des[1], i_des[0], "exit", 1);
		printf("ret = %d\n", ret);
	}

	return 0;
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
	return 0;
}

int
try_execute_command(int cid, int ifd, int ofd, const char *command, int is_echo)
{
	fd_set rfds, rtmp;
	int nfd, ret, n, response = 0, len;
	struct timeval login_timeout;
	char buf[1024], *p;

	FD_ZERO(&rfds);
	FD_SET(ofd, &rfds);
	nfd = ofd + 1;
	bzero(buf, sizeof(buf));
	p = buf;
	len = sizeof(buf);

	/* Input command */
	writen(ifd, (void *) command, strlen(command));

	if (is_echo)
	{
		fprintf(stderr, "command is \"%s\"\n", command);
	}

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));
		login_timeout.tv_sec = 1;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Catch a signal from child process */
			if (errno == EINTR)
			{
				kill_child_process(cid, 9);
				wait_child_process(cid, NULL);
				return -1;
			}

			return -1;
		}
		else if (ret == 0)
		{
			// fprintf( stderr, "timeout.\n" );

			/* Input command */
			if (is_echo)
			{
				/* Maybe login successed */
				if (response = 1)
				{
					/* Echo is right */
					if (strcasecmp(buf, command) == 0)
					{
						break;
					}
					/* Echo is wrong, it's not a shell */
					else
					{
						fprintf(stderr, "Echo is wrong, it's not in a shell.\n");
						kill_child_process(cid, 9);
						wait_child_process(cid, NULL);
						return -1;
					}
				}
				/* This is not a shell */
				else
				{
					kill_child_process(cid, 9);
					wait_child_process(cid, NULL);
					return -1;
				}
			}
			/* Input password */
			else
			{
				if (response = 1)
				{
					/* No echo is right */
					if (strcasecmp(buf, command) != 0)
					{
						break;
					}
					/* Echo is wrong, it's not a shell */
					else
					{
						fprintf(stderr, "echo is wrong %s\n", buf);
						kill_child_process(cid, 9);
						wait_child_process(cid, NULL);
						return -1;
					}
				}
				/* This is not a shell */
				else
				{
					kill_child_process(cid, 9);
					wait_child_process(cid, NULL);
					return -1;
				}
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;

			n = read(ofd, p, len);
			p = p + n;
			len = len - n;

			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(0, buf, n);
			}

			// fprintf( stderr, "outpipe. n = %d\n", n );
		}

	}

	/* Input 0x0d */
	writen(ifd, "\x0d", 1);
	fprintf(stderr, "input huiche\n");

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));
		login_timeout.tv_sec = 1;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Catch a signal from child process */
			if (errno == EINTR)
			{
				fprintf(stderr, "stderr?\n");
				kill_child_process(cid, 9);
				wait_child_process(cid, NULL);
				return -1;
			}
			fprintf(stderr, "ret<0?\n");
			return -1;
		}
		else if (ret == 0)
		{
			fprintf(stderr, "timeout.\n");

			/* Maybe login successed */
			if (response = 1)
			{
				break;
			}
			/* This is not a shell */
			else
			{
				fprintf(stderr, "stderr?\n");
				kill_child_process(cid, 9);
				wait_child_process(cid, NULL);
				return -1;
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			bzero(buf, sizeof(buf));
			n = read(ofd, buf, sizeof(buf));
			// fprintf( stderr, "outpipe. n = %d\n", n );

			if (n == 0 && strcmp(command, "exit"))
			{
				return -1;
			}
			else if (n == 0 && strcmp(command, "exit") == 0)
			{
				return 0;
			}
			else
			{
				writen(0, buf, n);
			}

		}

	}

	return 0;
}

int
try_telnet_login(int cid, int ifd, int ofd, int efd)
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

		login_timeout.tv_sec = 15;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Cacth child process */
			if (errno == EINTR)
			{
				// wait( NULL );
				return -1;
			}

			return -1;
		}
		else if (ret == 0)
		{
			fprintf(stderr, "timeout.\n");

			/* Maybe login successed */
			if (response = 1)
			{
				// kill( cid, 9 );
				// wait( NULL );
				break;
			}
			/* Login failed */
			else
			{
				kill_child_process(cid, 9);
				wait_child_process(cid, NULL);
				return -1;
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			bzero(buf, sizeof(buf));
			n = read(ofd, buf, sizeof(buf));

			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(0, buf, n);
			}

			fprintf(stderr, "outpipe. n = %d\n", n);
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
				writen(0, buf, n);
			}

			fprintf(stderr, "Recv stderr message.");
			kill(cid, 9);
			wait(NULL);
			return -1;
		}

	}

	/* It's time to input password */
	writen(ifd, "freesvr\x0d", 8);

	while (1)
	{
		memcpy(&rtmp, &rfds, sizeof(rfds));

		login_timeout.tv_sec = 15;
		login_timeout.tv_usec = 0;

		ret = select(nfd, &rtmp, NULL, NULL, &login_timeout);

		if (ret < 0)
		{
			/* Cacth child process */
			if (errno == EINTR)
			{
				// wait( NULL );
				return -1;
			}

			return -1;
		}
		else if (ret == 0)
		{
			fprintf(stderr, "timeout.\n");

			/* Maybe login successed */
			if (response = 1)
			{
				// kill( cid, 9 );
				// wait( NULL );
				return 0;
			}
			/* Login failed */
			else
			{
				kill_child_process(cid, 9);
				wait_child_process(cid, NULL);
				return -1;
			}
		}

		/* Recv message from stdout */
		if (FD_ISSET(ofd, &rtmp))
		{
			response = 1;
			bzero(buf, sizeof(buf));
			n = read(ofd, buf, sizeof(buf));

			if (n == 0)
			{
				return -1;
			}
			else
			{
				writen(0, buf, n);
			}

			fprintf(stderr, "outpipe. n = %d\n", n);
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
				writen(0, buf, n);
			}

			fprintf(stderr, "Recv stderr message.");
			kill(cid, 9);
			wait(NULL);
			return -1;
		}

	}
	return -1;
}

int
main(int argc, char *argv[])
{
	telnet_modify_password(argv);
	return 0;
}
