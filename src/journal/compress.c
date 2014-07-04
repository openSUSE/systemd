/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <lzma.h>

#include "macro.h"
#include "util.h"
#include "compress.h"

bool compress_blob(const void *src, uint64_t src_size, void *dst, uint64_t *dst_size) {
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        bool b = false;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

        /* Returns false if we couldn't compress the data or the
         * compressed result is longer than the original */

        ret = lzma_easy_encoder(&s, LZMA_PRESET_DEFAULT, LZMA_CHECK_NONE);
        if (ret != LZMA_OK)
                return false;

        s.next_in = src;
        s.avail_in = src_size;
        s.next_out = dst;
        s.avail_out = src_size;

        /* Does it fit? */
        if (lzma_code(&s, LZMA_FINISH) != LZMA_STREAM_END)
                goto fail;

        /* Is it actually shorter? */
        if (s.avail_out == 0)
                goto fail;

        *dst_size = src_size - s.avail_out;
        b = true;

fail:
        lzma_end(&s);

        return b;
}

bool uncompress_blob(const void *src, uint64_t src_size,
                     void **dst, uint64_t *dst_alloc_size, uint64_t* dst_size, uint64_t dst_max) {

        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        uint64_t space;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size);
        assert(dst_size);
        assert(*dst_alloc_size == 0 || *dst);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return false;

        space = MIN(src_size * 2, dst_max ?: (uint64_t) -1);
        if (!greedy_realloc(dst, dst_alloc_size, space))
                return false;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *dst;
        s.avail_out = space;

        for (;;) {
                uint64_t used;

                ret = lzma_code(&s, LZMA_FINISH);

                if (ret == LZMA_STREAM_END)
                        break;

                if (ret != LZMA_OK)
                        return false;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;

                if (dst_max > 0 && space == dst_max)
                        return false;

                used = space - s.avail_out;
                space = MIN(2 * space, dst_max ?: (uint64_t) -1);
                if (!greedy_realloc(dst, dst_alloc_size, space))
                        return false;

                s.avail_out = space - used;
                s.next_out = *dst + used;
        }

        *dst_size = space - s.avail_out;
        return true;
}

bool uncompress_startswith(const void *src, uint64_t src_size,
                           void **buffer, uint64_t *buffer_size,
                           const void *prefix, uint64_t prefix_len,
                           uint8_t extra) {

        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;

        /* Checks whether the uncompressed blob starts with the
         * mentioned prefix. The byte extra needs to follow the
         * prefix */

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(buffer_size);
        assert(prefix);
        assert(*buffer_size == 0 || *buffer);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return false;

        if (!(greedy_realloc(buffer, buffer_size, prefix_len + 1)))
                return false;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = *buffer_size;

        for (;;) {
                ret = lzma_code(&s, LZMA_FINISH);

                if (ret != LZMA_STREAM_END && ret != LZMA_OK)
                        return false;

                if (*buffer_size - s.avail_out >= prefix_len + 1)
                        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                                ((const uint8_t*) *buffer)[prefix_len] == extra;

                if (ret == LZMA_STREAM_END)
                        return false;

                s.avail_out += *buffer_size;

                if (!(greedy_realloc(buffer, buffer_size, *buffer_size * 2)))
                        return false;

                s.next_out = *buffer + *buffer_size - s.avail_out;
        }
}
