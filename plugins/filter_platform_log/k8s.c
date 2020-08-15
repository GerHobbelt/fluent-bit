#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>

#include <sys/stat.h>

#include "k8s.h"

static int file_to_buffer(const char *path,
                          char **out_buf, size_t *out_size)
{
    int ret;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

struct k8s_conf *k8s_create(struct flb_filter_instance *ins, struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct k8s_conf *k8s;

    k8s = flb_calloc(1, sizeof(struct k8s_conf));
    if (!k8s) {
        return NULL;
    }

    /* process parameters */
    tmp = flb_filter_get_property("K8s_Host", ins);
    if (tmp) {
        k8s->api_host = flb_strdup(tmp);
    } else {
        k8s->api_host = flb_strdup(PLATFORM_LOG_K8S_API_HOST);
    }

    tmp = flb_filter_get_property("K8s_Port", ins);
    if (tmp && (ret = atoi(tmp)) > 1) {
        k8s->api_port = atoi(tmp);
    } else {
        k8s->api_port = PLATFORM_LOG_K8S_API_PORT;
    }

    k8s->use_tls = FLB_TRUE;
    tmp = flb_filter_get_property("K8s_Use_TLS", ins);
    if (tmp) {
        if (strcasecmp(tmp, "false") == 0 || strcasecmp(tmp, "no") == 0) {
            k8s->use_tls = FLB_FALSE;
        }
    }

    tmp = flb_filter_get_property("K8s_CA_File", ins);
    if (tmp) {
        k8s->tls_ca_file = flb_strdup(tmp);
    } else {
        k8s->tls_ca_file = flb_strdup(PLATFORM_LOG_K8S_CA_FILE);
    }

    tmp = flb_filter_get_property("K8s_Token_File", ins);
    if (tmp) {
        k8s->token_file = flb_strdup(tmp);
    } else {
        k8s->token_file = flb_strdup(PLATFORM_LOG_K8S_TOKEN_FILE);
    }

    flb_plg_debug(ins, "k8s_api=%s:%i (use_tls=%i)", k8s->api_host, k8s->api_port, k8s->use_tls);
    flb_plg_debug(ins, "k8s_tls_ca_file=%s", k8s->tls_ca_file);
    flb_plg_debug(ins, "k8s_token_file=%s", k8s->token_file);

    /* compute HTTP Authorization header */
    char *tk = NULL;
    size_t tk_size = 0;
    ret = file_to_buffer(k8s->token_file, &tk, &tk_size);
    if (ret != 0) {
        flb_free(tk);
        k8s_destroy(k8s);
        return NULL;
    }

    k8s->auth = flb_malloc(tk_size + 32);
    k8s->auth_len = snprintf(k8s->auth, tk_size + 32, "Bearer %s", tk);

    flb_free(tk);

    /* initialize network - inline here but could be split out for lazy-init */
    /* stolen from to plugins/filter_kubernetes/kube_meta.c:flb_kube_network_init() */
    int io_type = FLB_IO_TCP;
    k8s->upstream = NULL;

    if (k8s->use_tls == FLB_TRUE) {
        k8s->tls.context = flb_tls_context_new(FLB_TRUE, // tls_verify,
                                               FLB_TRUE, // tls_debug,
                                               NULL,     // tls_vhost,
                                               NULL,     // tls_ca_path,
                                               k8s->tls_ca_file,
                                               NULL,     // tls_crt_file
                                               NULL,     // tls_key_file
                                               NULL);    // tls_key_passwd
        if (!k8s->tls.context) {
            k8s_destroy(k8s);
            return NULL;
        }
        io_type = FLB_IO_TLS;
    }

    /* Create an Upstream context */
    k8s->upstream = flb_upstream_create(config, k8s->api_host, k8s->api_port, io_type, &k8s->tls);
    if (!k8s->upstream) {
        k8s_destroy(k8s);
        return NULL;
    }

    /* Remove async flag from upstream */
    k8s->upstream->flags &= ~(FLB_IO_ASYNC);

    k8s->ins = ins;

    return k8s;
}

void k8s_destroy(struct k8s_conf *k8s)
{
    if (k8s->upstream) {
        flb_upstream_destroy(k8s->upstream);
    }
    if (k8s->tls.context) {
        flb_tls_context_destroy(k8s->tls.context);
    }
    if (k8s->auth) {
        flb_free(k8s->auth);
    }
    if (k8s->token_file) {
        flb_free(k8s->token_file);
    }
    if (k8s->tls_ca_file) {
        flb_free(k8s->tls_ca_file);
    }
    if (k8s->api_host) {
        flb_free(k8s->api_host);
    }
    flb_free(k8s);
}

/* perform a GET and return the http status code, or -1 if an error occured */
int k8s_http_get(struct k8s_conf *k8s, const char *uri, char **out_buf, size_t *out_bytes)
{
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(k8s->upstream);
    if (!u_conn) {
        flb_plg_warn(k8s->ins, "connection error");
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_GET, uri,
                        NULL, 0,  //body / body_len
                        NULL, 0,  //host / port
                        NULL, 0); //proxy / flags
    if (!c) {
        flb_error("count not create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_buffer_size(c, 32768/*ctx->buffer_size*/); //TODO
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Connection", 10, "close", 5);
    flb_http_add_header(c, "Authorization", 13, k8s->auth, k8s->auth_len);

    int ret;
    size_t b_sent;

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        return -1;
    }
    flb_plg_debug(k8s->ins, "http_do=%i, HTTP Status=%i", ret, c->resp.status);
    // fprintf(stderr, "%.*s", (int)c->resp.payload_size, c->resp.payload);

    char *ret_buf;
    ret_buf = flb_malloc(c->resp.payload_size);
    memcpy(ret_buf, c->resp.payload, c->resp.payload_size);

    ret        = c->resp.status;
    *out_buf   = ret_buf;
    *out_bytes = c->resp.payload_size;

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return ret;
}

int k8s_pl_list(struct k8s_conf *k8s, char **out_buf, size_t *out_bytes)
{
    int ret;
    int root_type;
    int packed;
    char *resp;
    size_t resp_size;
    char *buf;
    size_t size;

    ret = k8s_http_get(k8s, PLATFORM_LOG_K8S_LIST_API, &resp, &resp_size);
    if (ret == -1) {
        return -1;
    }

    // TODO: use flb_pack_json_state() for big json
    packed = flb_pack_json(resp, resp_size, &buf, &size, &root_type);
    flb_plg_debug(k8s->ins, "(list) flb_pack_json result: %i", packed);
    flb_free(resp);
    if (packed == -1) {
        return -1;
    }

    *out_buf   = buf;
    *out_bytes = size;

    return ret;
}

int k8s_pl_delta(struct k8s_conf *k8s, char **out_buf, size_t *out_bytes)
{
    return 410;
}

int k8s_pl_delta_wip(struct k8s_conf *k8s, char **out_buf, size_t *out_bytes)
{
    int ret;
    int packed;
    int root_type;
    char *buf;
    size_t size;
    char *pl_stream = NULL;
    size_t pl_stream_size = 0;
    char *pl_json = NULL;
    size_t pl_json_size = 0;

    char *rv;
    char *uri;
    int tmp_len;

    rv = "164251";

    tmp_len = strlen(PLATFORM_LOG_K8S_WATCH_API_FMT) + strlen(rv);
    uri = flb_malloc(tmp_len);
    snprintf(uri, tmp_len - 1, PLATFORM_LOG_K8S_WATCH_API_FMT, rv);

    ret = k8s_http_get(k8s, uri, &pl_stream, &pl_stream_size);
    if (ret == -1) {
        flb_free(uri);
        return -1;
    }

    flb_free(uri);

    /*
        delta is a stream of json strings, so we put them in an array to create a
        single json string that can be packed ont its own
        otherwise, flb_pack_json stops after the first valid json
    */

    // TODO: realloc; if same pointer, memmove / memset
    pl_json_size = pl_stream_size + 2;
    pl_json = flb_malloc(pl_json_size * sizeof(char));
    if (!pl_json) {
        return -1;
    }
    strncat(pl_json, "[", 1);
    strncat(pl_json, pl_stream, pl_stream_size);
    strncat(pl_json, "]", 1);

    // TODO: use flb_pack_json_state() for big json
    packed = flb_pack_json(pl_json, pl_json_size, &buf, &size, &root_type);
    flb_plg_debug(k8s->ins, "(delta) flb_pack_json result: %i", packed);

    flb_free(pl_json);
    flb_free(pl_stream);

    if (packed == -1) {
        return -1;
    }

    *out_buf   = buf;
    *out_bytes = size;

    return ret;
}
