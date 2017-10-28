#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
test_lock()
{
	int ret, fd;
	char buf[256];

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s/LOCK", BINARY_PATH);
	fd = open(buf, O_WRONLY | O_CREAT, 0644);

	if (fd == -1)
	{
		perror("Open LOCK file failed");
		return -1;
	}

	ret = flock(fd, LOCK_EX | LOCK_NB);

	if (ret == -1)
	{
		close(fd);
		return -1;
	}

	return fd;
}
