#ifndef FLB_FILTER_PLATFORM_LOG_CACHE_H
#define FLB_FILTER_PLATFORM_LOG_CACHE_H

#include <msgpack.h>

struct cache {
    struct flb_hash *_hash;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;
};

struct cache *cache_create(struct flb_filter_instance *ins, size_t size, int max_size);
void cache_destroy(struct cache *cache);

int cache_add(struct cache *cache, const char *key, int key_len, msgpack_object *value);
int cache_del(struct cache *cache, const char *key);

int cache_get(struct cache *cache, const char *key, int key_len, msgpack_object *value);

int cache_size(struct cache *cache);
int cache_clear(struct cache *cache);

void cache_dump(struct cache *cache);

#endif
