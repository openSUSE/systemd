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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "mkdir.h"
#include "path-util.h"

int main(int argc, char **argv) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *rule_path = "/run/udev/rules.d/10-root-symlink.rules";
        struct stat root_stat;
        int root_major, root_minor;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc > 1) {
                log_error("This program takes no arguments.");
                return EXIT_FAILURE;
        }

        umask(0022);

        if (stat("/", &root_stat) != 0) {
                log_debug("Failed to stat '/': %m");
                return EXIT_SUCCESS;
        }

        root_major = major(root_stat.st_dev);
        root_minor = minor(root_stat.st_dev);
        if (root_major <= 0)
                return EXIT_SUCCESS;

        mkdir_parents(rule_path, 0755);

        f = fopen(rule_path, "wxe");
        if (!f) {
                log_error("Failed to create udev rule file %s: %m", rule_path);
                return EXIT_FAILURE;
        }

        fprintf(f,
                "ACTION==\"add|change\","
                "SUBSYSTEM==\"block\","
                "ENV{MAJOR}==\"%d\","
                "ENV{MINOR}==\"%d\","
                "SYMLINK+=\"root\"\n",
                root_major, root_minor);

        return EXIT_SUCCESS;
}
