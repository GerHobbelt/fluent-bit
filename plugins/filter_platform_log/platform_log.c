#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_upstream.h>

/* re-emitter stuff */
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_storage.h>

#include <msgpack.h>
#include <jsmn/jsmn.h>

#include "platform_log.h"
#include "cache.h"
#include "k8s.h"

/*
 * utils
 */
static inline int key_cmp(const char *str, int len, const char *cmp)
{
    if (strlen(cmp) != len) {
        return -1;
    }
    return strncasecmp(str, cmp, len);
}

msgpack_object *helper_msgpack_map_get(const char *key,
                           msgpack_object_map *map)
{

    msgpack_object_kv *kv = map->ptr;
    msgpack_object *k;
    static msgpack_object *v = NULL;
    for (int i = 0; i < map->size; i++) {
        k = &(kv+i)->key;
        v = &(kv+i)->val;

        if (key_cmp(k->via.str.ptr, k->via.str.size, key) == 0) {
            return v;
        }
    }
    return NULL;
}

int platform_log_get_inputs_output(struct msgpack_object *pl,
                                   msgpack_object *inputs,
                                   msgpack_object *output)
{
    int i_found, o_found;

    i_found = FLB_FALSE;
    o_found = FLB_FALSE;

    if (pl->type == MSGPACK_OBJECT_MAP) {
        msgpack_object_kv *kv = pl->via.map.ptr;
        msgpack_object *k, *v = NULL;
        for (int i = 0; i < pl->via.map.size; i++) {
            k = &(kv+i)->key;
            v = &(kv+i)->val;
            if (key_cmp(k->via.str.ptr, k->via.str.size, "spec") == 0) {
                return platform_log_get_inputs_output(v, inputs, output);
            }
            if (key_cmp(k->via.str.ptr, k->via.str.size, "inputs") == 0) {
                *inputs = *v;
                i_found = FLB_TRUE;
            }
            if (key_cmp(k->via.str.ptr, k->via.str.size, "output") == 0) {
                *output = *v;
                o_found = FLB_TRUE;
            }
        }
    }

    return i_found && o_found;
}

// given an output object, retrieve the splunk info
// note: this could be bundled with platform_log_get_inputs_output
// since we only support a single output today, but in case we expand in the future
int platform_log_get_output_splunk(struct msgpack_object *out,
                                   msgpack_object *splunk)
{
    int ret = FLB_FALSE;
    if (out->type == MSGPACK_OBJECT_ARRAY && out->via.array.size == 1) {
        msgpack_object spl_obj = out->via.array.ptr[0];
        if (spl_obj.type == MSGPACK_OBJECT_MAP && spl_obj.via.map.size == 1) {
            *splunk = spl_obj.via.map.ptr[0].val;
            ret = FLB_TRUE;
             // todo: test if "key" == "splunk"; recurse too!
        }
    }
    return ret;
}

int platform_log_get_inputs_envoy_fqdns(struct msgpack_object *in,
                                        msgpack_object *fqdns)
{

    int ret = FLB_FALSE;
    if (in->type == MSGPACK_OBJECT_ARRAY) {
        for (int i=0; i<in->via.array.size; i++) {
            return platform_log_get_inputs_envoy_fqdns(&(in->via.array.ptr[i]), fqdns);
        }
    } else if (in->type == MSGPACK_OBJECT_MAP) {
        msgpack_object_kv *kv = in->via.map.ptr;
        msgpack_object *k;
        msgpack_object *v;
        for (int i=0; i<in->via.map.size; i++) {
            k = &(kv+i)->key;
            v = &(kv+i)->val;
            if (key_cmp(k->via.str.ptr, k->via.str.size, "envoy") == 0) {
                return platform_log_get_inputs_envoy_fqdns(v, fqdns);
            }
            if (key_cmp(k->via.str.ptr, k->via.str.size, "fqdns") == 0) {
                *fqdns = *v;
                ret = v->type == MSGPACK_OBJECT_ARRAY;
            }
        };
    }
    return ret;
}


/* envoy cache CRUD helpers */
static int envoy_cache_add(struct platform_log_ctx *ctx,
                    const char *fqdn, int fqdn_len, msgpack_object *splunk)
{
    flb_plg_debug(ctx->ins, "(cache) adding fqdn: %.*s", fqdn_len, fqdn);
    return cache_add(ctx->cache, fqdn, fqdn_len, splunk);
}

static int envoy_cache_delete(struct platform_log_ctx *ctx,
                       const char *fqdn, int fqdn_len, msgpack_object *splunk)
{
    int ret;
    flb_sds_t s;

    flb_plg_debug(ctx->ins, "(cache) deleting fqdn: %.*s", fqdn_len, fqdn);
    // need to create a '\0'-terminated string here
    s = flb_sds_create_len(fqdn, fqdn_len);
    ret = cache_del(ctx->cache, s);
    flb_sds_destroy(s);
    return ret;
}

static int envoy_cache_update(struct platform_log_ctx *ctx,
                       const char *fqdn, int fqdn_len, msgpack_object *splunk)
{
    flb_plg_error(ctx->ins, "envoy_cache_update not implemented");
    return FLB_TRUE;
}

/*
   obj is either a PlatformLog or PlatformLogList
   either way, use .metadata.resourceVersion
 */
static int set_resource_version(struct platform_log_ctx *ctx, msgpack_object *obj)
{
    msgpack_object *metadata = NULL;
    msgpack_object *rv = NULL;

    metadata = helper_msgpack_map_get("metadata", &obj->via.map);
    if (metadata == NULL) {
        return FLB_FALSE;
    }
    rv = helper_msgpack_map_get("resourceVersion", &metadata->via.map);
    if (rv == NULL) {
        return FLB_FALSE;
    }
    // rv should be MSGPACK_OBJECT_STR

    char *old = ctx->rv;
    ctx->rv = flb_strndup(rv->via.str.ptr, rv->via.str.size);
    if (old != NULL) {
        flb_free(old);
    }

    return FLB_TRUE;
}

// Takes a msgpack-ed PlatformLog object and apply the given cache CRUD function to it
static int platform_log_apply_fn(struct platform_log_ctx *ctx, msgpack_object *pl,
                          int(*f) (struct platform_log_ctx *ctx,
                                   const char *key, int key_len, msgpack_object *value))
{
    int ret = FLB_TRUE;
    msgpack_object inputs, output;
    int tmp;

    tmp = platform_log_get_inputs_output(pl, &inputs, &output);

    if (tmp == FLB_TRUE) { //check for array type here?
        msgpack_object splunk;
        msgpack_object fqdns;

        int have_splunk = platform_log_get_output_splunk(&output, &splunk);
        int have_fqdns = platform_log_get_inputs_envoy_fqdns(&inputs, &fqdns);

        if (have_splunk && have_fqdns) {
            // now loop through each fqdns and add it to the cache
            msgpack_object_str fqdn;
            for (int i=0; i<fqdns.via.array.size; i++) {
                if (fqdns.via.array.ptr[i].type == MSGPACK_OBJECT_STR) {
                    fqdn = fqdns.via.array.ptr[i].via.str;
                    int r = (*f) (ctx, fqdn.ptr, fqdn.size, &splunk);
                    ret &= r;
                }
            }
        }
    } else {
        flb_plg_debug(ctx->ins, "(apply) platform_log_get_inputs_output returned nothing...");
        // TODO: might need to print this for debugging
        // msgpack_object_print(stderr, *pl);
        // fprintf(stderr, "\n");
    }
    return ret;
}

// int platform_log_list_apply_fn ()
// {
//     return 0;
// }

int load_data(struct platform_log_ctx *ctx)
{
    int ret;
    char *buf;
    size_t size;

    ret = k8s_pl_list(ctx->k8s, &buf, &size);
    flb_plg_debug(ctx->ins, "k8s_pl_list result %i", ret);
    if (ret != 200) {
        return -1;
    }

    msgpack_unpacked result;
    size_t off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    flb_plg_debug(ctx->ins, "msgpack_unpack_next %i", ret);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_free(buf);
        return -1;
    }

    // we should have a MSGPACK_OBJECT_MAP (7) now.
    // iterate to find the keys.

    msgpack_object *items;
    items = helper_msgpack_map_get("items", &result.data.via.map);
    if (items != NULL) {
        msgpack_object *elem;
        for (int j = 0; j < items->via.array.size; j++) {
            elem = &(items->via.array.ptr[j]);
            platform_log_apply_fn(ctx, elem, &envoy_cache_add);
        }
    }

    ctx->updated = time(NULL);
    ret = set_resource_version(ctx, &result.data);
    flb_plg_debug(ctx->ins, "set_resource_version %i", ret);

    msgpack_unpacked_destroy(&result);
    flb_free(buf);

    flb_plg_debug(ctx->ins, "load completed=%i resource_version=%s", ctx->updated, ctx->rv);

    return ret;
}

int load_delta(struct platform_log_ctx *ctx)
{
    int ret;
    char *buf;
    size_t size;

    ret = k8s_pl_delta(ctx->k8s, &buf, &size);
    flb_plg_debug(ctx->ins, "k8s_pl_delta result %i", ret);
    if (ret != 200) {
        return ret;
    }

    msgpack_unpacked result;
    size_t off = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);

    msgpack_object *pl = NULL;
    if (result.data.type == MSGPACK_OBJECT_ARRAY) {
        msgpack_object *elem;

        for (int i=0; i<result.data.via.array.size; i++) {
            elem = &(result.data.via.array.ptr[i]);
            /*
                elem is a map with 2 keys:
                type: ADDED | DELETED | MODIFIED
                object: a platform_log object
            */

            if (elem->type != MSGPACK_OBJECT_MAP) {
                fprintf(stderr, "(delta) not a map!\n");
                continue;
            }

            int(*f)(struct platform_log_ctx *ctx, const char *key, int key_len,
                    msgpack_object *value) = NULL;

            msgpack_object_map *map;
            msgpack_object_kv *kv;
            msgpack_object *k;
            msgpack_object *v;

            map = &elem->via.map;
            kv = map->ptr;

            for (int j = 0; j < map->size; j++) {
                k = &(kv+j)->key;
                v = &(kv+j)->val;

                if (key_cmp(k->via.str.ptr, k->via.str.size, "type") == 0) {
                   if (key_cmp(v->via.str.ptr, v->via.str.size, "ADDED") == 0) {
                       f = &envoy_cache_add;
                   } else if (key_cmp(v->via.str.ptr, v->via.str.size, "DELETED") == 0) {
                       f = &envoy_cache_delete;
                   } else if (key_cmp(v->via.str.ptr, v->via.str.size, "MODIFIED") == 0) {
                       f = &envoy_cache_update;
                   }
                   continue;
                }

                if (key_cmp(k->via.str.ptr, k->via.str.size, "object") == 0) {
                   pl = v;
                }
           }

            if (pl && f) {
                platform_log_apply_fn(ctx, pl, f);
            }
        }

    } else {
        fprintf(stderr, "--- couldn't parse delta\n");
    }

    msgpack_unpacked_destroy(&result);

    ctx->updated = time(NULL);
    // use the resourceVersion from the last pl object
    if (pl != NULL) {
        set_resource_version(ctx, pl);
    }
    flb_plg_debug(ctx->ins, "delta completed=%i resource_version=%s", ctx->updated, ctx->rv);

    return ret;
}

// helper to add directly to cache
static void cache_add_txt(struct cache *cache,
                      const char *key, int key_len,
                      const char *index, int index_len,
                      const char *server, int server_len)
{
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pk, 2); // index + server

    // splunk index
    msgpack_pack_str(&pk, PLATFORM_LOG_INDEX_KEY_LEN);
    msgpack_pack_str_body(&pk, PLATFORM_LOG_INDEX_KEY, PLATFORM_LOG_INDEX_KEY_LEN);
    msgpack_pack_str(&pk, index_len);
    msgpack_pack_str_body(&pk, index, index_len);

    //splunk server
    msgpack_pack_str(&pk, PLATFORM_LOG_SERVER_KEY_LEN);
    msgpack_pack_str_body(&pk, PLATFORM_LOG_SERVER_KEY, PLATFORM_LOG_SERVER_KEY_LEN);
    msgpack_pack_str(&pk, server_len);
    msgpack_pack_str_body(&pk, server, server_len);

    // flb_hash_add(cache->_hash, key, key_len, sbuf.data, sbuf.size);

    msgpack_unpacked result;
    size_t off = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);
    cache_add(cache, key, key_len, &result.data);
    msgpack_unpacked_destroy(&result);


    msgpack_sbuffer_destroy(&sbuf);
}

void cache_create_dummy_data(struct platform_log_ctx *ctx)
{
    struct data {
        char *fqdn;
        char *index;
        char *server;
    };
    struct data entries[] = {
        {"dummy1.sandbox.cloud.adobe.io", "dummy-index1", "dummy-server1"},
        {"dummy2.sandbox.cloud.adobe.io", "dummy-index2", "dummy-server2"},
        {"laurent-o.sandbox.cloud.adobe.io", "lr-dummy-index", "lr-dummy-server"},
    };
    for (int i=0; i<sizeof(entries) / sizeof(struct data); i++) {
        cache_add_txt(ctx->cache,
                  entries[i].fqdn, strlen(entries[i].fqdn),
                  entries[i].index, strlen(entries[i].index),
                  entries[i].server, strlen(entries[i].server));
    }
}


/*
* filter utils
*/
static int configure(struct platform_log_ctx *ctx, struct flb_config *config)
{
    const char *tmp;
    char *type_envoy = PLATFORM_LOG_ENVOY_KEY;

    ctx->key = NULL;
    ctx->rv = NULL;

    /* Process filter properties */
    tmp = flb_filter_get_property("key", ctx->ins);
    if (tmp) {
        ctx->key = flb_strdup(tmp);
    } else {
        ctx->key = flb_strdup(PLATFORM_LOG_LOG_KEY);
    }

    tmp = flb_filter_get_property("type", ctx->ins);
    if (tmp) {
        if (strcmp(tmp, PLATFORM_LOG_ENVOY_KEY) == 0) {
            ctx->type = ENVOY;
        } else {
            flb_plg_error(ctx->ins, "Configuration \"Type\" has invalid value "
                          "'%s'. Only 'envoy' is supported\n",
                          tmp);
          return -1;
        }
    } else {
        ctx->type = ENVOY;
    }

    // initialize cache
    ctx->cache = cache_create(ctx->ins, PLATFORM_CACHE_SIZE, PLATFORM_CACHE_SIZE_MAX);
    if (ctx->cache == NULL) {
        flb_errno();
        return -1;
    }
    flb_plg_debug(ctx->ins, "cache configured...");
    // cache_create_dummy_data(ctx);

    // initialize k8s
    ctx->k8s = k8s_create(ctx->ins, config);
    if (ctx->k8s == NULL) {
        flb_errno();
        return -1;
    }
    flb_plg_debug(ctx->ins, "k8s configured...");

    // k8s_test(ctx->k8s, config); // TODO: test success.....
    load_data(ctx);
    // cache_dump(ctx->cache);

    // TODO: parameterize
    ctx->ttl = PLATFORM_CACHE_TTL_SECS;

    flb_plg_info(ctx->ins, "type=%s key=%s cache=%i", type_envoy, ctx->key, cache_size(ctx->cache));

    // re-emitter stuff
    // from rewrite_tag.c
    int ret;
    int coll_fd;
    struct flb_input_instance *ins;
    const char *emitter_name = "envoy_re_emiter";
    const char *emitter_storage_type = "filesystem";

    ret = flb_input_name_exists(emitter_name, config);
    if (ret == FLB_TRUE) {
        flb_plg_error(ctx->ins, "emitter_name '%s' already exists", emitter_name);
        return -1;
    }

    ins = flb_input_new(config, "emitter", NULL, FLB_FALSE);
    if (!ins) {
        flb_plg_error(ctx->ins, "cannot create emitter instance");
        return -1;
    }

    /* Set the alias name */
    // ret = flb_input_set_property(ins, "alias", ctx->emitter_name);
    ret = flb_input_set_property(ins, "alias", emitter_name);
    if (ret == -1) {
        flb_plg_warn(ctx->ins,
                     "cannot set emitter_name, using fallback name '%s'",
                     ins->name);
    }

    /* Set the emitter_mem_buf_limit */
    // if(ctx->emitter_mem_buf_limit > 0) {
    //     ins->mem_buf_limit = ctx->emitter_mem_buf_limit;
    // }

    /* Set the storage type */
    ret = flb_input_set_property(ins, "storage.type", emitter_storage_type);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot set storage.type");
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(ins, config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize emitter instance '%s'", ins->name);
        flb_input_instance_exit(ins, config);
        flb_input_instance_destroy(ins);
        return -1;
    }

    /* Retrieve the collector id registered on the in_emitter initialization */
    coll_fd = in_emitter_get_collector_id(ins);

    /* Initialize plugin collector (event callback) */
    flb_input_collector_start(coll_fd, ins);

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(ctx->emitter_name, ins->metrics);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot set metrics title, using fallback name %s",
                     ins->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(config->cio, ins);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize storage for stream '%s'",
                      ctx->emitter_name);
        return -1;
    }

    ctx->ins_emitter = ins;
    ctx->config = config;

    return 0;
}

static void teardown(struct platform_log_ctx *ctx)
{
    // emitter stuff
    flb_input_instance_exit(ctx->ins_emitter, ctx->config);
    flb_input_instance_destroy(ctx->ins_emitter);

    flb_free(ctx->rv);
    k8s_destroy(ctx->k8s);
    flb_free(ctx->key);
    cache_destroy(ctx->cache);
    flb_plg_info(ctx->ins, "stopped");
}


// TODO: return fqdn as a msgpack_object?
static inline int extract_fqdn(msgpack_object* log,
                               const char **fqdn, size_t *fqdn_size,
                               struct platform_log_ctx *ctx)
{
    /*
        only handle json-formatted Envoy logs, which msgpack would have already
        deserialized into a map
    */
    if (log->type != MSGPACK_OBJECT_MAP)
    {
        flb_plg_trace(ctx->ins, "(fqdn) ignoring log type %u", log->type);
        return 0;
    }

    msgpack_object *ret;
    ret = helper_msgpack_map_get(PLATFORM_LOG_FQDN_KEY, &log->via.map);
    if (ret != NULL) {
        flb_plg_trace(ctx->ins, "(fqdn) found '%.*s'", ret->via.str.size, ret->via.str.ptr);
        *fqdn = ret->via.str.ptr;
        *fqdn_size = ret->via.str.size;
        return 1;
    } else {
        flb_plg_trace(ctx->ins, "(fqdn) FQDN not found");
    }
    return 0;
}

/* re-pack the entire object and re-emit it */
static inline int re_emit(msgpack_object ts, msgpack_object map,
                          msgpack_object info,
                          struct platform_log_ctx *ctx)
{
    int i;
    msgpack_object_kv *kv = map.via.map.ptr;

    flb_plg_debug(ctx->ins, "(emit) found useful record, re-emitting (NEW)");

    /* info is a map: {index=>"idx", name=>"server"} */
    /* add the index, use the name as a tag to re-emit the record */
    msgpack_object *index, *name;
    index = helper_msgpack_map_get("index", &info.via.map);
    name = helper_msgpack_map_get("name", &info.via.map);

    if (!(index && name)) {
        flb_plg_debug(ctx->ins, "(emit) no splunk info, ignoring...");
        return 0;
    }

    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    // char *out_tag = "lrtag"; // should be the index!

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* repack with the additional info */
    msgpack_pack_array(&packer, 2);
    msgpack_pack_object(&packer, ts);

    /* existing map + index map (from info map) + src map */
    msgpack_pack_map(&packer, map.via.map.size + 2);

    /* existing map */
    for (i = 0; i < map.via.map.size; i++) {
        msgpack_pack_object(&packer, (kv+i)->key);
        msgpack_pack_object(&packer, (kv+i)->val);
    }

    /* info map */
    msgpack_pack_str(&packer, PLATFORM_LOG_INDEX_KEY_LEN);
    msgpack_pack_str_body(&packer, PLATFORM_LOG_INDEX_KEY, PLATFORM_LOG_INDEX_KEY_LEN);
    msgpack_pack_str(&packer, index->via.str.size);
    msgpack_pack_str_body(&packer, index->via.str.ptr, index->via.str.size);


    /* src map */
    // TODO: cache this in ctx?
    msgpack_pack_str(&packer, PLATFORM_LOG_SRC_KEY_LEN);
    msgpack_pack_str_body(&packer, PLATFORM_LOG_SRC_KEY, PLATFORM_LOG_SRC_KEY_LEN);
    msgpack_pack_str(&packer, PLATFORM_LOG_ENVOY_KEY_LEN);
    msgpack_pack_str_body(&packer, PLATFORM_LOG_ENVOY_KEY, PLATFORM_LOG_ENVOY_KEY_LEN);


    int r = in_emitter_add_record(name->via.str.ptr, name->via.str.size, sbuf.data, sbuf.size, ctx->ins_emitter);
    flb_plg_debug(ctx->ins, "(emit) re-emitting result %i", r);

    msgpack_sbuffer_destroy(&sbuf);

    return 0;
}

static inline int apply_envoy_filter(/*msgpack_packer *packer,*/
                                     msgpack_object *root,
                                     struct platform_log_ctx *ctx)
{
    int ret = 0;

    // Record format
    // [1123123, {"log"=>{"authority"=>"a.b.io", "path"->"/"}, "stream"=>"stdout", "time"=>"..."}]
    // we're only interested in the configured key K == ctx->key

    // msgpack_object_print(stderr, *root);
    // fprintf(stderr, "\n");

    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1]; //flb_time_pop_from_msgpack(&tm, &result, &obj);

    if (map.type != MSGPACK_OBJECT_MAP) {
        flb_plg_warn(ctx->ins, "(envoy) unexpected log format %u", map.type);
        return 0;
    }

    int i;
    msgpack_object_kv *kv = map.via.map.ptr;
    msgpack_object *key;
    msgpack_object *val;

    const char *fqdn;
    size_t fqdn_size;

    /* first pass - check if the records was re-emitted */
    for (i = 0; i < map.via.map.size; i++) {
        key = &(kv+i)->key;
        // val = &(kv+i)->val;
        if (key_cmp(key->via.str.ptr, key->via.str.size, PLATFORM_LOG_INDEX_KEY) == 0) {
            flb_plg_debug(ctx->ins, "(envoy) found re-emitted record, exit");
            return 0;
        }
    }

    for (i = 0; i < map.via.map.size; i++) {
        key = &(kv+i)->key;
        val = &(kv+i)->val;

        if (key_cmp(key->via.str.ptr, key->via.str.size, ctx->key) == 0) {
            flb_plg_trace(ctx->ins, "(envoy) key found, initiating fqdn extraction");

            ret = extract_fqdn(val, &fqdn, &fqdn_size, ctx);
            if ( ret == 1 ) {
                flb_plg_trace(ctx->ins, "(envoy) found fqdn '%.*s'", (int)fqdn_size, fqdn);

                const char *info_val;
                int info_val_size;
                ret = cache_get(ctx->cache, fqdn, fqdn_size, &info_val, &info_val_size);
                if ( ret == 1 ) {
                    flb_plg_debug(ctx->ins, "(envoy) found splunk info for fqdn '%.*s'", (int)fqdn_size, fqdn);

                    msgpack_unpacked result;
                    size_t off = 0;
                    msgpack_unpacked_init(&result);
                    msgpack_unpack_next(&result, info_val, info_val_size, &off);
                    re_emit(ts, map, result.data, ctx);
                    msgpack_unpacked_destroy(&result);

                    ret = 1;
                } else {
                    flb_plg_trace(ctx->ins, "(envoy) splunk info not found");
                }

            } else {
                // flb_plg_trace(ctx->ins, "(envoy) fqdn not found");
                // trace?
            }
            break;
        }
    }

    // no changes for now: we could have configurable option to drop the message.
    return 0;
}


/*
* filter proper
*/
static int cb_pl_init(struct flb_filter_instance *f_ins,
                      struct flb_config *config, void *data)
{
    struct platform_log_ctx *ctx;

    ctx = flb_malloc(sizeof(struct platform_log_ctx));
    if (!ctx) {
      flb_errno();
      return -1;
    }
    ctx->ins = f_ins;

    flb_plg_info(f_ins, "initializing...");
    if (configure(ctx, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_pl_filter(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        void **out_buf, size_t *out_bytes,
                        struct flb_filter_instance *f_ins,
                        void *filter_context, struct flb_config *config)
{
    struct platform_log_ctx *ctx = filter_context;
    (void) f_ins;
    (void) config;
    time_t cache_age;
    int cache_s;

    flb_plg_debug(ctx->ins, "*** PLATFORM LOG FILTER :: BEGIN ***");

    flb_plg_debug(ctx->ins, "updated %i, rv %s", ctx->updated, ctx->rv);

    /* refresh cache if needed */
    cache_age = time(NULL) - ctx->updated;
    if (cache_age > ctx->ttl /*|| FLB_TRUE*/) {
        flb_plg_debug(ctx->ins, "cache updated %is ago, refreshing", cache_age);
        int delta;

        delta = load_delta(ctx);
        flb_plg_debug(ctx->ins, "delta %i", delta);
        if (delta == 410) {
            int full;
            flb_plg_debug(ctx->ins, "delta returned %i, clearing cache and reloading full", delta);
            cache_clear(ctx->cache);
            full = load_data(ctx);
            flb_plg_debug(ctx->ins, "full load result %i", full);
        }
    } else{
        flb_plg_debug(ctx->ins, "cache updated %is ago, refresh not needed", cache_age);
    }

    cache_s = cache_size(ctx->cache);
    flb_plg_debug(ctx->ins, "cache=%i", cache_s);

    // no mappings, no touch.
    if (cache_s == 0) {
        return FLB_FILTER_NOTOUCH;
    }

    int modified_records = 0;
    int total_modifications = 0;

    size_t off = 0;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    msgpack_unpacked result;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    /*
     * Records come in the format,
     *
     * [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ],
     * [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ]
     *
     * Example records:
     * [1123123, {"log"=>"{"authority":"a.b.io","path":"/"}"}]
     * [1123123, {"log"=>{"authority"=>"a.b.io", "path"->"/"}, "stream"=>"stdout", "time"=>"..."}] - envoy log
     * [1123123, {"log"=>{"authority"=>"a.b.io", "path"->"/"}, "stream"=>"stdout", "time"=>"...", "index"=>"my-idx"}] - re-emitted envoy log
     * [1123123, {"log"=>"[2020-06-24T18:29:19.328Z] "GET /ping HTTP/1.1" 200", "stream"=>"stdout", "time"=>"..."}] - non-json envoy log
     * [1123123, {"log"=>"I am log", "stream"=>"stdout", "time"=>"..."}] - non-json log
     *
     * If a json record already contains an "index" key, then either we re-emitted it or it has a
     * hard-coded index: let it through
     */

    /* Iterate each item array and add splunk info */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        modified_records = 0;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            flb_plg_warn(ctx->ins, "unexpected record format %i", result.data.type);
            msgpack_pack_object(&packer, result.data);
            // fprintf(stderr, "---\n");
            // msgpack_object_print(stderr, result.data);
            // fprintf(stderr, "\n---\n");
            continue;
        }

        if (ctx->type == ENVOY) {
            modified_records = apply_envoy_filter(/*&packer, */&result.data, ctx);
        }

        if (modified_records == 00) {
            // noop, so copy original event.
            msgpack_pack_object(&packer, result.data);
        }
        total_modifications += modified_records;

    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf   = buffer.data;
    *out_bytes = buffer.size;

    if (total_modifications == 0) {
        msgpack_sbuffer_destroy(&buffer);
        flb_plg_debug(ctx->ins, "*** PLATFORM LOG FILTER :: END / NO MODIF ***");
        return FLB_FILTER_NOTOUCH;
    }
    flb_plg_debug(ctx->ins, "*** PLATFORM LOG FILTER :: END / WITH MODIF ***");
    return FLB_FILTER_MODIFIED;
}

static int cb_pl_exit(void *data, struct flb_config *config)
{
    struct platform_log_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
/* only write context to k8s_conf! */
static struct flb_config_map config_map[] = {
    /* platform_log */
    {
     FLB_CONFIG_MAP_STR, "type", NULL,
     0, FLB_FALSE, 0,
     "Platform Log source type; only envoy is supported at the moment"
    },

    {
     FLB_CONFIG_MAP_STR, "key", NULL,
     0, FLB_FALSE, 0,
     "Input log key where the payload is located"
    },

    /* k8s */
    {
     FLB_CONFIG_MAP_STR, "k8s_host", PLATFORM_LOG_K8S_API_HOST,
     0, FLB_TRUE, offsetof(struct k8s_conf, api_host),
     "Kubernetes API server host"
    },
    {
     FLB_CONFIG_MAP_INT, "k8s_port", PLATFORM_LOG_K8S_API_PORT,
     0, FLB_TRUE, offsetof(struct k8s_conf, api_port),
     "Kubernetes API server port"
    },
    {
     FLB_CONFIG_MAP_BOOL, "k8s_use_tls", "true",
     0, FLB_TRUE, offsetof(struct k8s_conf, use_tls),
     "Kubernetes API server uses TLS"
    },
    {
     FLB_CONFIG_MAP_STR, "k8s_ca_file", PLATFORM_LOG_K8S_CA_FILE,
     0, FLB_TRUE, offsetof(struct k8s_conf, tls_ca_file),
     "Kubernetes TLS CA file"
    },
    /*
    {
     FLB_CONFIG_MAP_STR, "k8s_ca_path", NULL,
     0, FLB_TRUE, offsetof(struct k8s_conf, tls_ca_path),
     "Kubernetes TLS ca path"
    },
    */
    {
     FLB_CONFIG_MAP_STR, "k8s_token_file", PLATFORM_LOG_K8S_TOKEN_FILE,
     0, FLB_TRUE, offsetof(struct k8s_conf, token_file),
     "Kubernetes authorization token file"
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_platform_log_plugin = {
    .name        = "platform_log",
    .description = "Adobe Platform Log Filter",
    .cb_init     = cb_pl_init,
    .cb_filter   = cb_pl_filter,
    .cb_exit     = cb_pl_exit,
    .config_map  = config_map,
    .flags       = 0
};
