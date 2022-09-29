#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_mem.h>

#include "cache.h"

/*
 * caching
 *
 * a hasmap of msgpack objects
 */
struct cache *cache_create(struct flb_filter_instance *ins, size_t size, int max_size)
{
    struct cache *cache;

    cache = flb_malloc(sizeof(struct cache));
    if (!cache) {
        flb_errno();
        return NULL;
    }
    // NOTE: we should use FLB_HASH_EVICT_LESS_USED
    // but it's not implemented...
    cache->_hash = flb_hash_create(FLB_HASH_EVICT_RANDOM, size, max_size);
    if (!cache->_hash) {
        flb_free(cache);
        return NULL;
    }
    cache->ins = ins;

    return cache;
}

void cache_destroy(struct cache *cache)
{
    flb_hash_destroy(cache->_hash);
    flb_free(cache);
}

int cache_add(struct cache *cache, const char *key, int key_len, msgpack_object *value)
{
    int ret;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_object(&pk, *value);
    ret = flb_hash_add(cache->_hash, key, key_len, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    if (ret == -1) {
        flb_plg_error(cache->ins, "(cache_add) error adding %.*s to cache", key_len, key);
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

int cache_del(struct cache *cache, const char *key)
{
    flb_hash_del(cache->_hash, key);
    return FLB_TRUE;
}

/* let the client unpack so we don't have to deep-copy the msgpack_object */
int cache_get(struct cache *cache, const char *key, int key_len,
                                   const char **val, int *val_len)
{
    int ret;
    const char *tmp_val;
    size_t tmp_size;

    ret = flb_hash_get(cache->_hash, key, key_len, &tmp_val, &tmp_size);
    if (ret != -1) {
        *val = tmp_val;
        *val_len = tmp_size;
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

int cache_size(struct cache *cache)
{
    return cache->_hash->total_count;
}

int cache_clear(struct cache *cache)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;

    mk_list_foreach_safe(head, tmp, &cache->_hash->entries) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);
        flb_plg_debug(cache->ins, "(clear) deleting %.*s", (int)entry->key_len, entry->key);
        cache_del(cache, entry->key);
    }
    return FLB_TRUE;
}

void cache_dump(struct cache *cache)
{
    int i = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;

    int ret;
    flb_sds_t buf;
    size_t size = 128; //should be enough to hold {index->foo, name->bar}
    buf = flb_sds_create_size(size);
    if (!buf) {
        flb_plg_debug(cache->ins, "cache dump not available");
        return;
    }

    flb_plg_debug(cache->ins, "== dumping cache: nb entries %i ==", cache->_hash->total_count);
    mk_list_foreach_safe(head, tmp, &cache->_hash->entries) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);

        msgpack_unpacked result;
        size_t off = 0;

        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, entry->val, entry->val_size, &off);
        ret = msgpack_object_print_buffer(buf, size, result.data);
        flb_plg_debug(cache->ins, "> %i: %.*s => %.*s", i,
                      (int)entry->key_len, entry->key,
                      (int)ret, buf);
        msgpack_unpacked_destroy(&result);
        i++;
    }
    flb_sds_destroy(buf);

    flb_plg_debug(cache->ins, "== end cache dump ==", cache->_hash->total_count);
}
