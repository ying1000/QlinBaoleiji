#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#define ECHOFLAGS ( ECHO | ECHOE | ECHOK | ECHONL | ICANON)

int
set_disp_mode(int fd, int option)
{
	int err;
	struct termios term;
	if (tcgetattr(fd, &term) == -1)
	{
		printf("Cannot get the attribution of the terminal");
		return 1;
	}

	if (option)
		term.c_lflag |= ECHOFLAGS;
	else
		term.c_lflag &= ~ECHOFLAGS;
	err = tcsetattr(fd, TCSAFLUSH, &term);
	if (err == -1 && err == EINTR)
	{
		printf("Cannot set the attribution of the terminal");
		return 1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int f_des[2], g_des[2];
	int pid, n, nfd, ret, keyboard, connect = 1;
	char buf[1024];
	fd_set rfds;
	struct timeval timeout;

	bzero(buf, 1024);
	if (argc != 3)
	{
		printf("Usage: %s comand1 comand2\n", argv[0]);
		return 1;
	}

	if (pipe(f_des) == -1)
	{
		perror("cannot create the IPC pipe");
		return 1;
	}
	pipe(g_des);

	pid = fork();
	if (pid == -1)
	{
		perror("cannot create new process");
		return 1;
	}
	else if (pid == 0)
	{
		dup2(f_des[1], STDOUT_FILENO);
		dup2(g_des[0], STDIN_FILENO);

		close(f_des[0]);
		close(f_des[1]);

		close(g_des[0]);
		close(g_des[1]);

		// sleep(2);
		if (execlp("telnet", "telnet", "222.35.62.134", "230", NULL) == -1)
		{
			perror("in child process,cannot execute the command");
			return 1;
		}

		// sleep(1);
		return 1;
	}
	else
	{
		// dup2(f_des[0],STDIN_FILENO);

		// close(f_des[0]);
		close(f_des[1]);
		close(g_des[0]);

		/* if(execlp(argv[2],argv[2],NULL)==-1){ perror("in parent process,cannot execute the
		   command"); return 1; } */

		// sleep(1);
		// write( g_des[1], "hello\x0d", 6 );
		// sleep(1);
		// set_disp_mode( STDIN_FILENO, 0 );
		keyboard = open("/dev/pts/4", O_RDONLY | O_NONBLOCK);
		if (keyboard == -1)
		{
			perror("key");
		}

		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		// FD_SET(keyboard, &rfds);
		FD_SET(f_des[0], &rfds);

		nfd = f_des[0] + 1;
		// nfd = ( f_des[0] > keyboard ? f_des[0] : keyboard ) + 1;

		while (1)
		{
			// fprintf(stderr, "looping\n");
			// timeout.tv_sec = 0;
			// timeout.tv_usec = 200*1000;
			if (connect)
			{
				connect = 0;
				// timeout.tv_sec = 30;
				// timeout.tv_usec = 0;
				ret = select(nfd, &rfds, NULL, NULL, NULL);
			}
			else
			{
				timeout.tv_sec = 2;
				timeout.tv_usec = 800 * 1000;
				FD_ZERO(&rfds);
				FD_SET(STDIN_FILENO, &rfds);
				// FD_SET(keyboard, &rfds);
				FD_SET(f_des[0], &rfds);

				nfd = f_des[0] + 1;
				// nfd = ( f_des[0] > keyboard ? f_des[0] : keyboard ) + 1;
				ret = select(nfd, &rfds, NULL, NULL, NULL);
			}
			if (FD_ISSET(STDIN_FILENO, &rfds))
			{

				fprintf(stderr, "stdin\n");
				n = read(STDIN_FILENO, buf, sizeof(buf));
				write(g_des[1], buf, n);
			}
			if (ret == 0)		// timeout
			{
				// write( g_des[1], "exit\x0d", 5 );
				write(g_des[1], "passwd bergdino\x0d", 16);
				// fprintf(stderr, "timeout\n");

				// write( g_des[1], "ls\x0d", 3 );
				continue;
			}

			/* if ( FD_ISSET(keyboard,&rfds) ) { fprintf(stderr, "stdin\n"); n = read( keyboard,
			   buf, sizeof(buf) ); write( g_des[1], buf, n ); } */
			if (FD_ISSET(f_des[0], &rfds))
			{
				bzero(buf, sizeof(buf));
				n = read(f_des[0], buf, sizeof(buf));
				write(0, buf, n);
				// write( g_des[1], "ls\x0d", 3 );
			}

		}

		// n = read( f_des[0], buf, sizeof(buf) );
		// printf ("%s\n", buf );
		// write( 0, buf, n ); 
		// set_disp_mode( STDIN_FILENO, 1 );
		return 1;
	}

	return 0;
}
