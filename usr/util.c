#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

void daemon_init(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		exit(-1);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
}
