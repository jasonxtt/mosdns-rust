#ifndef MOSDNS_CACHE_CORE_H
#define MOSDNS_CACHE_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int status;
  int state;
  unsigned char* response_ptr;
  unsigned long long response_len;
  unsigned char* domain_set_ptr;
  unsigned long long domain_set_len;
} mosdns_cache_lookup_result;

typedef struct {
  int status;
  unsigned char* ptr;
  unsigned long long len;
} mosdns_cache_bytes_result;

const char* mosdns_cache_runtime_version(void);
int mosdns_cache_runtime_ping(void);
void* mosdns_cache_new(unsigned long long size,
                       unsigned int lazy_cache_ttl,
                       unsigned char enable_ecs,
                       const unsigned char* exclude_ips_ptr,
                       unsigned long long exclude_ips_len);
void mosdns_cache_free(void* handle);
mosdns_cache_lookup_result mosdns_cache_lookup(void* handle,
                                               const unsigned char* query_ptr,
                                               unsigned long long query_len,
                                               const unsigned char* ecs_ptr,
                                               unsigned long long ecs_len,
                                               long long now_unix_sec);
mosdns_cache_lookup_result mosdns_cache_lookup_by_key(void* handle,
                                                      const unsigned char* key_ptr,
                                                      unsigned long long key_len,
                                                      long long now_unix_sec);
int mosdns_cache_store(void* handle,
                       const unsigned char* query_ptr,
                       unsigned long long query_len,
                       const unsigned char* ecs_ptr,
                       unsigned long long ecs_len,
                       const unsigned char* response_ptr,
                       unsigned long long response_len,
                       const unsigned char* domain_set_ptr,
                       unsigned long long domain_set_len,
                       long long now_unix_sec);
int mosdns_cache_store_by_key(void* handle,
                              const unsigned char* key_ptr,
                              unsigned long long key_len,
                              const unsigned char* response_ptr,
                              unsigned long long response_len,
                              const unsigned char* domain_set_ptr,
                              unsigned long long domain_set_len,
                              long long now_unix_sec);
int mosdns_cache_flush(void* handle);
mosdns_cache_bytes_result mosdns_cache_export_dump(void* handle);
int mosdns_cache_import_dump(void* handle, const unsigned char* dump_ptr, unsigned long long dump_len);
void mosdns_cache_free_buffer(unsigned char* ptr, unsigned long long len);

#ifdef __cplusplus
}
#endif

#endif
