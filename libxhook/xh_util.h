#ifndef XH_UTIL_H_
#define XH_UTIL_H_

#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__LP64__)
#define XH_UTIL_FMT_LEN     "16"
#define XH_UTIL_FMT_X       "llx"
#else
#define XH_UTIL_FMT_LEN     "8"
#define XH_UTIL_FMT_X       "x"
#endif

#define XH_UTIL_FMT_FIXED_X XH_UTIL_FMT_LEN XH_UTIL_FMT_X
#define XH_UTIL_FMT_FIXED_S XH_UTIL_FMT_LEN "s"

int xh_util_get_mem_protect(uintptr_t addr, size_t len, const char *pathname, unsigned int *prot);
int xh_util_get_addr_protect(uintptr_t addr, const char *pathname, unsigned int *prot);
int xh_util_set_addr_protect(uintptr_t addr, unsigned int prot);
void xh_util_flush_instruction_cache(uintptr_t addr);
ssize_t xh_util_write_memory_safely(void* dest, uint8_t* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // XH_UTIL_H_ 
