/*
 * Copyright (C) 2014-2015 Robert Milasan <rmilasan@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE     128

#define _ROOTDEV_	"/"
#define _PATH_		"/run/udev/rules.d"
#define _FILE_		"10-root-symlink.rules"

int main()
{
	struct stat statbuf;

	if (stat(_ROOTDEV_, &statbuf) != 0)
		return 1;

	if (major(statbuf.st_dev) > 0) {
		int fd = -1;
		char filename[BUFFER_SIZE];

		if (mkdir(_PATH_, 0755) != 0 && errno != EEXIST)
			return errno;

		snprintf(filename, BUFFER_SIZE, "%s/%s", _PATH_, _FILE_);

		if ((fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1)
			return errno;
		else {
			char buf[BUFFER_SIZE];

			snprintf(buf, BUFFER_SIZE, "ACTION==\"add|change\", SUBSYSTEM==\"block\", ENV{MAJOR}==\"%d\", ENV{MINOR}==\"%d\", SYMLINK+=\"root\"\n",
				 major(statbuf.st_dev), minor(statbuf.st_dev));

			if (write(fd, buf, strlen(buf)) == -1)
				return errno;

			if (close(fd) == -1)
				return errno;
		}
	}

	return 0;
}
