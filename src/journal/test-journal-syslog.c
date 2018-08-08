/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include "alloc-util.h"
#include "journald-syslog.h"
#include "macro.h"
#include "string-util.h"
#include "syslog-util.h"

static void test_syslog_parse_identifier(const char *str,
                                         const char *ident, const char *pid, int ret) {
        const char *buf = str;
        _cleanup_free_ char *ident2 = NULL, *pid2 = NULL;
        int ret2;

        ret2 = syslog_parse_identifier(&buf, &ident2, &pid2);

        assert_se(ret == ret2);
        assert_se(ident == ident2 || streq_ptr(ident, ident2));
        assert_se(pid == pid2 || streq_ptr(pid, pid2));
}

static void test_syslog_parse_priority(const char *str, int priority, int ret) {
        const char *buf = str;
        int priority2, ret2;

        ret2 = syslog_parse_priority(&buf, &priority2, false);

        assert_se(ret == ret2);
        if (ret2 == 1)
                assert_se(priority == priority2);
}

int main(void) {
        test_syslog_parse_identifier("pidu[111]: xxx", "pidu", "111", 11);
        test_syslog_parse_identifier("pidu: xxx", "pidu", NULL, 6);
        test_syslog_parse_identifier("pidu:  xxx", "pidu", NULL, 7);
        test_syslog_parse_identifier("pidu xxx", NULL, NULL, 0);
        test_syslog_parse_identifier(":", "", NULL, 1);
        test_syslog_parse_identifier(":  ", "", NULL, 3);
        test_syslog_parse_identifier("pidu:", "pidu", NULL, 5);
        test_syslog_parse_identifier("pidu: ", "pidu", NULL, 6);
        test_syslog_parse_identifier("pidu : ", NULL, NULL, 0);

        test_syslog_parse_priority("<>", 0, 0);
        test_syslog_parse_priority("<>aaa", 0, 0);
        test_syslog_parse_priority("<aaaa>", 0, 0);
        test_syslog_parse_priority("<aaaa>aaa", 0, 0);
        test_syslog_parse_priority(" <aaaa>", 0, 0);
        test_syslog_parse_priority(" <aaaa>aaa", 0, 0);
        /* TODO: add test cases of valid priorities */

        return 0;
}
