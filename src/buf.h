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

void df_buf_free(df_buf *buf);

#endif
