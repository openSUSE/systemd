/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "id128-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static void test_chase_symlinks(void) {
        _cleanup_free_ char *result = NULL;
        char temp[] = "/tmp/test-chase.XXXXXX";
        const char *top, *p, *q;
        int r, pfd;

        assert_se(mkdtemp(temp));

        top = strjoina(temp, "/top");
        assert_se(mkdir(top, 0700) >= 0);

        p = strjoina(top, "/dot");
        assert_se(symlink(".", p) >= 0);

        p = strjoina(top, "/dotdot");
        assert_se(symlink("..", p) >= 0);

        p = strjoina(top, "/dotdota");
        assert_se(symlink("../a", p) >= 0);

        p = strjoina(temp, "/a");
        assert_se(symlink("b", p) >= 0);

        p = strjoina(temp, "/b");
        assert_se(symlink("/usr", p) >= 0);

        p = strjoina(temp, "/start");
        assert_se(symlink("top/dot/dotdota", p) >= 0);

        /* Paths that use symlinks underneath the "root" */

        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r == -ENOENT);

        q = strjoina(temp, "/usr");

        r = chase_symlinks(p, temp, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, q));

        assert_se(mkdir(q, 0700) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));

        p = strjoina(temp, "/slash");
        assert_se(symlink("/", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, temp));

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        assert_se(symlink("../../..", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, temp));

        p = strjoina(temp, "/6dotsusr");
        assert_se(symlink("../../../usr", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));

        p = strjoina(temp, "/top/8dotsusr");
        assert_se(symlink("../../../../usr", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        assert_se(symlink("///usr///", p) >= 0);

        result = mfree(result);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));

        result = mfree(result);
        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));

        /* Paths using . */

        result = mfree(result);
        r = chase_symlinks("/etc/./.././", NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));

        result = mfree(result);
        r = chase_symlinks("/etc/./.././", "/etc", 0, &result);
        assert_se(r > 0 && path_equal(result, "/etc"));

        result = mfree(result);
        r = chase_symlinks("/etc/machine-id/foo", NULL, 0, &result);
        assert_se(r == -ENOTDIR);

        /* Path that loops back to self */

        result = mfree(result);
        p = strjoina(temp, "/recursive-symlink");
        assert_se(symlink("recursive-symlink", p) >= 0);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == -ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        assert_se(symlink(q, p) >= 0);
        p = strjoina(temp, "/target/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        if (geteuid() == 0) {
                p = strjoina(temp, "/priv1");
                assert_se(mkdir(p, 0755) >= 0);

                q = strjoina(p, "/priv2");
                assert_se(mkdir(q, 0755) >= 0);

                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(q, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(p, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(q, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) == -EPERM);

                assert_se(rmdir(q) >= 0);
                assert_se(symlink("/etc/passwd", q) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) == -EPERM);

                assert_se(chown(p, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);
        }

        p = strjoina(temp, "/machine-id-test");
        assert_se(symlink("/usr/../etc/./machine-id", p) >= 0);

        pfd = chase_symlinks(p, NULL, CHASE_OPEN, NULL);
        if (pfd != -ENOENT) {
                char procfs[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(pfd) + 1];
                _cleanup_close_ int fd = -1;
                sd_id128_t a, b;

                assert_se(pfd >= 0);

                xsprintf(procfs, "/proc/self/fd/%i", pfd);

                fd = open(procfs, O_RDONLY|O_CLOEXEC);
                assert_se(fd >= 0);

                safe_close(pfd);

                assert_se(id128_read_fd(fd, ID128_PLAIN, &a) >= 0);
                assert_se(sd_id128_get_machine(&b) >= 0);
                assert_se(sd_id128_equal(a, b));
        }

        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_unlink_noerrno(void) {
        char name[] = "/tmp/test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);

        {
                PROTECT_ERRNO;
                errno = -42;
                assert_se(unlink_noerrno(name) >= 0);
                assert_se(errno == -42);
                assert_se(unlink_noerrno(name) < 0);
                assert_se(errno == -42);
        }
}

static void test_readlink_and_make_absolute(void) {
        char tempdir[] = "/tmp/test-readlink_and_make_absolute";
        char name[] = "/tmp/test-readlink_and_make_absolute/original";
        char name2[] = "test-readlink_and_make_absolute/original";
        char name_alias[] = "/tmp/test-readlink_and_make_absolute-alias";
        char *r = NULL;

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid(), false) >= 0);
        assert_se(touch(name) >= 0);

        assert_se(symlink(name, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(chdir(tempdir) >= 0);
        assert_se(symlink(name2, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_get_files_in_directory(void) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        assert_se(get_files_in_directory("/tmp", &l) >= 0);
        assert_se(get_files_in_directory(".", &t) >= 0);
        assert_se(get_files_in_directory(".", NULL) >= 0);
}

static void test_dot_or_dot_dot(void) {
        assert_se(!dot_or_dot_dot(NULL));
        assert_se(!dot_or_dot_dot(""));
        assert_se(!dot_or_dot_dot("xxx"));
        assert_se(dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot(".."));
        assert_se(!dot_or_dot_dot(".foo"));
        assert_se(!dot_or_dot_dot("..foo"));
}

int main(int argc, char *argv[]) {
        test_unlink_noerrno();
        test_readlink_and_make_absolute();
        test_get_files_in_directory();
        test_chase_symlinks();
        test_dot_or_dot_dot();

        return 0;
}
