#ifndef FLB_FILTER_PLATFORM_LOG_K8S_H
#define FLB_FILTER_PLATFORM_LOG_K8S_H

#include <fluent-bit/flb_upstream.h>

#define PLATFORM_LOG_K8S_API_HOST      "kubernetes.default.svc"
#define PLATFORM_LOG_K8S_API_PORT      443
#define PLATFORM_LOG_K8S_CA_FILE       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define PLATFORM_LOG_K8S_TOKEN_FILE    "/var/run/secrets/kubernetes.io/serviceaccount/token"

#define PLATFORM_LOG_K8S_LIST_API      "/apis/adobeplatform.adobe.io/v1alpha1/platformlogs"
#define PLATFORM_LOG_K8S_WATCH_API     "/apis/adobeplatform.adobe.io/v1alpha1/platformlogs?watch=1&resourceVersion="
#define PLATFORM_LOG_K8S_WATCH_API_FMT "/apis/adobeplatform.adobe.io/v1alpha1/platformlogs?watch=1&resourceVersion=%s"

struct k8s_conf {
    /* k8s API server */
    char *api_host;
    int api_port;
    char use_tls;
    char *tls_ca_file;

    /* k8s token file */
    char *token_file;
    char *token;
    size_t token_len;

    /* Pre-formatted HTTP Authorization header value */
    char *auth;
    size_t auth_len;

    struct flb_upstream *upstream;
    struct flb_tls tls;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;
};

struct k8s_conf *k8s_create(struct flb_filter_instance *ins, struct flb_config *config);
void k8s_destroy(struct k8s_conf *k8s);

int k8s_pl_list(struct k8s_conf *k8s, char **out_buf, size_t *out_bytes);
int k8s_pl_delta(struct k8s_conf *k8s, char **out_buf, size_t *out_bytes);

#endif
