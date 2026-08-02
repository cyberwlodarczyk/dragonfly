#include "shared.h"

peer *peer_init(int group)
{
    u8 *id = os_zalloc(ID_LEN);
    if (id == NULL)
    {
        return NULL;
    }
    if (crypto_rand_bytes(id, ID_LEN) != 0)
    {
        os_free(id);
        return NULL;
    }
    df_data *data = os_zalloc(sizeof(df_data));
    if (data == NULL)
    {
        os_free(id);
        return NULL;
    }
    if (dragonfly_set_group(data, group) != 0)
    {
        os_free(id);
        os_free(data);
        return NULL;
    }
    df_buf *commit = df_buf_alloc(DF_COMMIT_MAX_LEN);
    if (commit == NULL)
    {
        os_free(id);
        os_free(data);
        return NULL;
    }
    df_buf *confirm = df_buf_alloc(DF_CONFIRM_MAX_LEN);
    if (confirm == NULL)
    {
        os_free(id);
        os_free(data);
        os_free(commit);
        return NULL;
    }
    peer *p = os_zalloc(sizeof(peer));
    if (p == NULL)
    {
        os_free(id);
        os_free(data);
        os_free(commit);
        os_free(confirm);
        return NULL;
    }
    p->id = id;
    p->data = data;
    p->commit = commit;
    p->confirm = confirm;
    return p;
}

int peer_commit(peer *p, const u8 *other_id, const u8 *pwd)
{
    return dragonfly_commit(
        p->id,
        other_id,
        ID_LEN,
        pwd,
        PWD_LEN,
        p->data,
        p->commit);
}

int peer_process_commit(peer *p, const df_buf *other_commit)
{
    return dragonfly_process_commit(
        p->data,
        other_commit->buf,
        other_commit->used);
}

int peer_confirm(peer *p)
{
    return dragonfly_confirm(p->data, p->confirm);
}

int peer_check_confirm(peer *p, const df_buf *other_confirm)
{
    return dragonfly_check_confirm(
        p->data,
        other_confirm->buf,
        other_confirm->used);
}

void peer_free(peer *p)
{
    os_free(p->id);
    os_free(p->data);
    df_buf_free(p->commit);
    df_buf_free(p->confirm);
    os_free(p);
}

exchange *exchange_init(int group)
{
    peer *a = peer_init(group);
    if (a == NULL)
    {
        return NULL;
    }
    peer *b = peer_init(group);
    if (b == NULL)
    {
        peer_free(a);
        return NULL;
    }
    exchange *e = os_zalloc(sizeof(exchange));
    if (e == NULL)
    {
        peer_free(a);
        peer_free(b);
        return NULL;
    }
    e->a = a;
    e->b = b;
    return e;
}

int exchange_run(exchange *e, const u8 *pwd_a, const u8 *pwd_b)
{
    peer *a = e->a;
    peer *b = e->b;
    int ret = 0;
    if (peer_commit(a, b->id, pwd_a) != 0 ||
        peer_commit(b, a->id, pwd_b) != 0 ||
        peer_process_commit(a, b->commit) != 0 ||
        peer_process_commit(b, a->commit) != 0 ||
        peer_confirm(a) != 0 ||
        peer_confirm(b) != 0 ||
        peer_check_confirm(a, b->confirm) != 0 ||
        peer_check_confirm(b, a->confirm) != 0)
    {
        ret = -1;
    }
    return ret;
}

void exchange_free(exchange *e)
{
    peer_free(e->a);
    peer_free(e->b);
    os_free(e);
}
