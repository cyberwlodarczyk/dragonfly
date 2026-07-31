/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "buf.h"

#include <stdlib.h>

df_buf *df_buf_alloc(size_t len)
{
    df_buf *buf = os_zalloc(sizeof(df_buf) + len);
    if (buf == NULL)
    {
        return NULL;
    }
    buf->size = len;
    buf->buf = (u8 *)(buf + 1);
    return buf;
}

void *df_buf_put(df_buf *buf, size_t len)
{
    void *tmp = df_buf_mhead_u8(buf) + df_buf_len(buf);
    buf->used += len;
    if (buf->used > buf->size)
    {
        abort();
    }
    return tmp;
}

void df_buf_free(df_buf *buf)
{
    if (buf == NULL)
    {
        return;
    }
    if (buf->flags & DF_BUF_FLAG_EXT_DATA)
    {
        os_free(buf->buf);
    }
    os_free(buf);
}
