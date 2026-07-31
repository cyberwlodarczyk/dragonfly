/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "buf.h"

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
