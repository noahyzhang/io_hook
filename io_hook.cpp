#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include "libxhook/xhook_core.h"
#include "io_hook.h"

namespace io_hook {

static int (*original_open) (const char *pathname, int flags, mode_t mode);
static int (*original_open64) (const char *pathname, int flags, mode_t mode);
static ssize_t (*original_read) (int fd, void *buf, size_t size);
static ssize_t (*original_read_chk) (int fd, void* buf, size_t count, size_t buf_size);
static ssize_t (*original_write) (int fd, const void *buf, size_t size);
static ssize_t (*original_write_chk) (int fd, const void* buf, size_t count, size_t buf_size);
static int (*original_close) (int fd);
static int (*original_android_fdsan_close_with_tag) (int fd, uint64_t ownerId);

const static char* TARGET_MODULES[] = {
    "libc.so"
};
const static size_t TARGET_MODULE_COUNT = sizeof(TARGET_MODULES) / sizeof(char*);

extern "C" {

int ProxyOpen(const char* pathname, int flags, mode_t mode) {
    int ret = original_open(pathname, flags, mode);
    printf("call open func\n");
    return ret;
}

void do_hook() {
    for (int i = 0; i < TARGET_MODULE_COUNT; ++i) {
        const char* so_name = TARGET_MODULES[i];
        void* soinfo = open_elf_file(so_name);
        if (!soinfo) {
            printf("open %s failed\n", so_name);
            continue;
        }
        do_hook_symbol(soinfo, "open", (void*)ProxyOpen, (void**)&original_open);
        close_elf_file(soinfo);
    }
}

}  // extern "C"

}  // namespace io_hook
