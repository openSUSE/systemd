/*
 * numlock-on.c: Turn numlock-on
 *
 * This file may be freely copied under the terms of the GNU General
 * Public License (GPL), version 2, or at your option any later
 * version.

 * Copyright (C) 2013 Stanislav Brabec, SUSE
 *
 * based on setleds.c, which is
 * Copyright (C) 1994-1999 Andries E. Brouwer
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/kd.h>

int
main(int argc, char **argv) {
	char flags;

	if (ioctl(0, KDGKBLED, &flags)) {
		perror("KDGKBLED");
		exit(1);
	}

	if (ioctl(0, KDSKBLED, flags | LED_NUM | (LED_NUM << 4))) {
		perror("KDSKBLED");
		exit(1);
	}

	exit(0);
}
