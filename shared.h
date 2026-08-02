#ifndef SHARED_H
#define SHARED_H

#include "src/dragonfly.h"

#define ID_LEN 32
#define PWD_LEN 32

typedef struct
{
    u8 *id;
    df_data *data;
    df_buf *commit;
    df_buf *confirm;
} peer;

peer *peer_init(int group);

int peer_commit(peer *p, const u8 *other_id, const u8 *pwd);

int peer_process_commit(peer *p, const df_buf *other_commit);

int peer_confirm(peer *p);

int peer_check_confirm(peer *p, const df_buf *other_confirm);

void peer_free(peer *p);

typedef struct
{
    peer *a;
    peer *b;
} exchange;

exchange *exchange_init(int group);

int exchange_run(exchange *e, const u8 *pwd_a, const u8 *pwd_b);

void exchange_free(exchange *e);

#endif
