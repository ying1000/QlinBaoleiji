#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#define BUFSIZE 512
#define MAX_LINE_LEN 256

static char **Argv;
extern char *__progname, *__progname_full;
static char *LastArgv;

void
init_set_proc_title(int argc, char *argv[], char *envp[])
{
	int i, envpsize;
	extern char **environ;
	char **p;

	for (i = envpsize = 0; envp[i] != NULL; i++)
		envpsize += strlen(envp[i]) + 1;

	if ((p = (char **) malloc((i + 1) * sizeof(char *))) != NULL)
	{
		environ = p;

		for (i = 0; envp[i] != NULL; i++)
		{
			if ((environ[i] = malloc(strlen(envp[i]) + 1)) != NULL)
				strcpy(environ[i], envp[i]);
		}

		environ[i] = NULL;
	}

	/* Run through argv[] and envp[] checking how much contiguous space we have. This is the area
	   we can overwrite - start stored in Argv, and end in LastArgv */

	Argv = argv;
	for (i = 0; i < argc; i++)
		if (!i || (LastArgv + 1 == argv[i]))
			LastArgv = argv[i] + strlen(argv[i]);
	for (i = 0; envp[i] != NULL; i++)
		if ((LastArgv + 1) == envp[i])
			LastArgv = envp[i] + strlen(envp[i]);

	/* make glibc happy */
	__progname = strdup(PROGRAM_NAME);
	__progname_full = strdup(argv[0]);
}

void
set_proc_title(char *fmt, ...)
{
	va_list msg;
	static char statbuf[8192];
	char *p;
	int i, maxlen = (LastArgv - Argv[0]) - 2;

	va_start(msg, fmt);

	memset(statbuf, 0, sizeof(statbuf));
	vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

	va_end(msg);

	i = strlen(statbuf);

	sprintf(Argv[0], "%s", statbuf);
	p = &Argv[0][i];

	while (p < LastArgv)
		*p++ = '\0';
	Argv[1] = ((void *) 0);
}

static char *logfile;

int
init_log(void)
{
	logfile = config.log_file;

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

const char *
str_time(void)
{
	static char tstr[32];
	static char buf[32];
	struct tm *tm;
	const char *fmt = "%Y.%m.%d-%H:%M:%S";

	struct timeval tv;
	gettimeofday(&tv, NULL);

	time_t caltime = tv.tv_sec;

	memset(tstr, 0x00, sizeof(tstr));
	memset(buf, 0x00, sizeof(buf));

	if ((tm = localtime(&caltime)) == NULL)
		return (NULL);

	if (strftime(tstr, sizeof(tstr) - 1, fmt, tm) == 0)
		return (NULL);

	snprintf(buf, sizeof(buf), "%s.%06ld", tstr, tv.tv_usec);

	return (buf);
}

void
write_log(const char *msg, ...)
{
	char *buf = NULL;
	int sz = MAX_LINE_LEN, n;
	va_list argptr;

	/* Modified from printf(3) man page */
	do
	{
		if ((buf = realloc(buf, sz)) == NULL)
			exit(0);
		// die(ERROR, "Out of memory.", 0, 0, -1);

		va_start(argptr, msg);
		n = vsnprintf(buf, sz, msg, argptr);
		va_end(argptr);

		if (n == -1)			/* glibc 2.0 */
			sz *= 2;			/* Try a bigger buffer */
		else if (n >= sz)		/* C99 compliant / glibc 2.1 */
			sz = n + 1;			/* precisely what is needed */
		else
			break;				/* It worked */
	}
	while (1);

	if (logfile && config.write_local_log)
	{
		char *s;
		s = (char *) malloc(BUFSIZE);
		bzero(s, BUFSIZE);

		snprintf(s, BUFSIZE, "[%s]%s[%d] %s\n", str_time(), PROGRAM_NAME, getpid(), buf);
		write(2, s, strlen(s));
		free(s);
	}
	free(buf);
}
