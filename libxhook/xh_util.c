#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "xh_util.h"
#include "xh_maps.h"

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

static int xh_util_get_mem_protect_maps_iter_cb(void* data, uintptr_t start, uintptr_t end, char* perms,
                                                int offset, char* pathname)
{
    uintptr_t start_addr = *(uintptr_t*) ((void**) data)[0];
    uintptr_t end_addr = *(uintptr_t*) ((void**) data)[1];
    const char* expected_pathname = *(const char**) ((void**) data)[2];
    unsigned int* prot = *(unsigned int**) ((void**) data)[3];
    int* load0 = (int*) ((void**) data)[4];
    int* found_all = (int*) ((void**) data)[5];

    // Use addr to locate map entry is enough.
    // Use pathname to locate map entry may fail if expected map entry was mapped directly from apk. In this case
    // map entry name is always the apk path while our expect name is the so path.
    // if (pathname != NULL && strcmp(expected_pathname, pathname) != 0) return 0;

    if(perms[3] != 'p') return 0;

    *prot = 0;

    if(start_addr >= start && start_addr < end)
    {
        if(*load0)
        {
            //first load segment
            if(perms[0] == 'r') *prot |= PROT_READ;
            if(perms[1] == 'w') *prot |= PROT_WRITE;
            if(perms[2] == 'x') *prot |= PROT_EXEC;
            *load0 = 0;
        }
        else
        {
            //others
            if(perms[0] != 'r') *prot &= ~PROT_READ;
            if(perms[1] != 'w') *prot &= ~PROT_WRITE;
            if(perms[2] != 'x') *prot &= ~PROT_EXEC;
        }

        if(end_addr <= end)
        {
            *found_all = 1;
            return 1; //finished
        }
        else
        {
            start_addr = end; //try to find the next load segment
        }
    }

    return 0;
}

int xh_util_get_mem_protect(uintptr_t addr, size_t len, const char *pathname, unsigned int *prot)
{
    uintptr_t end_addr = addr + len;

    *prot = 0;

    int load0 = 1;
    int found_all = 0;
    void* iter_args[] = { &addr, &end_addr, &pathname, &prot, &load0, &found_all };
    xh_maps_iterate((xh_maps_iterate_cb_t) xh_util_get_mem_protect_maps_iter_cb, iter_args);

    if (!found_all) return -1;
    
    return 0;
}

int xh_util_get_addr_protect(uintptr_t addr, const char *pathname, unsigned int *prot)
{
    return xh_util_get_mem_protect(addr, sizeof(addr), pathname, prot);
}

int xh_util_set_addr_protect(uintptr_t addr, unsigned int prot)
{
    if(0 != mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), (int)prot))
        return 0 == errno ? -1 : errno;
    
    return 0;
}

void xh_util_flush_instruction_cache(uintptr_t addr)
{
    __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));
}

#if __ANDROID_API__ >= 23
#define xh_util_process_vm_writev process_vm_writev
#else
static ssize_t xh_util_process_vm_writev(pid_t __pid,
                                         const struct iovec* __local_iov,
                                         unsigned long __local_iov_count,
                                         const struct iovec* __remote_iov,
                                         unsigned long __remote_iov_count,
                                         unsigned long __flags)
{
    return syscall(__NR_process_vm_writev, __pid, __local_iov, __local_iov_count,
                   __remote_iov, __remote_iov_count, __flags);
}
#endif

ssize_t xh_util_write_memory_safely(void* dest, uint8_t* buf, size_t size)
{
    pid_t pid = getpid();
    struct iovec src_vec[] = {
            { .iov_base = buf, .iov_len = size }
    };
    struct iovec dest_vec[] = {
            { .iov_base = dest, .iov_len = size }
    };
    // return bytes written on success, -1 on failure.
    return xh_util_process_vm_writev(pid,
                                     src_vec, sizeof(src_vec) / sizeof(struct iovec),
                                     dest_vec, sizeof(dest_vec) / sizeof(struct iovec),
                                     0);
}