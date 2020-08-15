#ifndef FLB_FILTER_PLATFORM_LOG_H
#define FLB_FILTER_PLATFORM_LOG_H

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_input.h>

#include <time.h>

#define PLATFORM_LOG_LOG_KEY           "log"
#define PLATFORM_LOG_LOG_KEY_LEN       3
#define PLATFORM_LOG_FQDN_KEY          "authority"
#define PLATFORM_LOG_FQDN_KEY_LEN      9
#define PLATFORM_LOG_ENVOY_KEY         "envoy"
#define PLATFORM_LOG_ENVOY_KEY_LEN     5

/* source or sourcetype: need standard! */
#define PLATFORM_LOG_SRC_KEY           "source"
#define PLATFORM_LOG_SRC_KEY_LEN        6

/* TODO: retire this if not needed */
#define PLATFORM_LOG_INDEX_KEY         "index"
#define PLATFORM_LOG_INDEX_KEY_LEN     5
#define PLATFORM_LOG_SERVER_KEY        "splunk-server"
#define PLATFORM_LOG_SERVER_KEY_LEN    13

#define PLATFORM_CACHE_SIZE            10
#define PLATFORM_CACHE_SIZE_MAX        20
#define PLATFORM_CACHE_TTL_SECS        20 //240 /* should be less than 5min */

#define PLATFORM_LOG_METRIC_EMITTED    299
#define PLATFORM_LOG_MEM_BUF_LIMIT     "10M"

enum FILTER_PLATFORM_LOG_SOURCE_TYPE {
  ENVOY
};

struct platform_log_ctx {
    enum FILTER_PLATFORM_LOG_SOURCE_TYPE type;

    /* log key to match on */
    char *key;

    /* cache */
    struct cache *cache;
    time_t updated;
    time_t ttl;

    /* k8s parameters */
    struct k8s_conf *k8s;

    /* last resourceVersion */
    char *rv;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;

    /* emitter setup */
    struct flb_input_instance *ins_emitter; /* emitter input plugin instance */
    flb_sds_t emitter_name;                 /* emitter input plugin name */
    flb_sds_t emitter_storage_type;         /* emitter storage type */
    size_t emitter_mem_buf_limit;           /* emitter buffer limit */

    /* Fluent Bit context */
    struct flb_config *config;
};

/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in);
int in_emitter_get_collector_id(struct flb_input_instance *in);

#endif
