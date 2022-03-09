set(src
  cache.c
  k8s.c
  platform_log.c
)

FLB_PLUGIN(filter_platform_log "${src}" "")
