#include <unistd.h>
#include <pwd.h>
#include <sys/errno.h>
#include <sys/types.h>

static struct passwd root_pw = {
	.pw_name = "root",
};

struct passwd*
getpwuid(uid_t uid)
{
	if (uid == 0)
		return &root_pw;
	else {
		errno = ENOENT;
		return 0;
	}
}

