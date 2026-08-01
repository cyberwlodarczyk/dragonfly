/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DF_BUF_H
#define DF_BUF_H

#include "common.h"

#define DF_BUF_FLAG_EXT_DATA BIT(0)

typedef struct
{
    size_t size;
    size_t used;
    u8 *buf;
    u32 flags;
} df_buf;

df_buf *df_buf_alloc(size_t len);

void *df_buf_put(df_buf *buf, size_t len);

/**
 * df_buf_head - Get pointer to the head of the buffer data
 * @buf: df_buf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline const void *df_buf_head(const df_buf *buf)
{
    return buf->buf;
}

/**
 * df_buf_mhead - Get modifiable pointer to the head of the buffer data
 * @buf: df_buf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline void *df_buf_mhead(df_buf *buf)
{
    return buf->buf;
}

static inline u8 *df_buf_mhead_u8(df_buf *buf)
{
    return (u8 *)df_buf_mhead(buf);
}

/**
 * df_buf_len - Get the current length of a df_buf buffer data
 * @buf: df_buf buffer
 * Returns: Currently used length of the buffer
 */
static inline size_t df_buf_len(const df_buf *buf)
{
    return buf->used;
}

static inline void df_buf_put_data(df_buf *buf, const void *data, size_t len)
{
    if (data)
    {
        os_memcpy(df_buf_put(buf, len), data, len);
    }
}

static inline void df_buf_put_buf(df_buf *dst, const df_buf *src)
{
    df_buf_put_data(dst, df_buf_head(src), df_buf_len(src));
}

static inline void df_buf_put_le16(df_buf *buf, u16 data)
{
    u8 *pos = (u8 *)df_buf_put(buf, 2);
    PUT_LE16(pos, data);
}

void df_buf_free(df_buf *buf);

#endif
