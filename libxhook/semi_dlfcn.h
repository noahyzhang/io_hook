#ifndef SEMI_DLFCN_H_
#define SEMI_DLFCN_H_

#include <stddef.h>
#include <dlfcn.h>
#include <link.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*iterate_callback)(struct dl_phdr_info *info, size_t info_size, void *data);

int semi_dl_iterate_phdr(iterate_callback cb, void *data);

void* semi_dlopen(const char* pathname);

void* semi_dlsym(const void* semi_hlib, const char* sym_name);

void semi_dlclose(void* semi_hlib);

#ifdef __cplusplus
}
#endif

#endif  // SEMI_DLFCN_H_
