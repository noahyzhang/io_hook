#ifdef __linux
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE  // make sure dladdr is declared
    #endif 
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <errno.h>
#include <dlfcn.h>
#include <semi_dlfcn.h>
#include <stddef.h>
#include <link.h>
#include <signal.h>
#include "xhook_core.h"
#include "xh_log.h"
#include "xh_elf.h"
#include "tree.h"

static int              xh_core_sigsegv_enable = 1; //enable by default
// static struct sigaction xh_core_sigsegv_act_old;
static volatile int     xh_core_sigsegv_flag = 0;
static sigjmp_buf       xh_core_sigsegv_env;

// 来自于 /proc/self/maps
typedef struct xh_core_map_info {
    char* pathname;
    uintptr_t bias_addr;
    ElfW(Phdr)* phdrs;
    ElfW(Half) phdr_count;
    xh_elf_t elf;
    RB_ENTRY(xh_core_map_info) link;
} xh_core_map_info_t;

typedef struct xh_single_so_iterate_args {
    const char* path_suffix;
    xh_core_map_info_t* mi;
} xh_single_so_iterate_args_t;

//ELF header checker
int xh_elf_check_elfheader(uintptr_t base_addr)
{
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base_addr;

    //check magic
    if(0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return -1;

    //check class (64/32)
#if defined(__LP64__)
    if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return -1;
#else
    if(ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return -1;
#endif

    //check endian (little/big)
    if(ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return -1;

    //check version
    if(EV_CURRENT != ehdr->e_ident[EI_VERSION]) return -1;

    //check type
    if(ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return -1;

    //check machine
#if defined(__arm__)
    if(EM_ARM != ehdr->e_machine) return -1;
#elif defined(__aarch64__)
    if(EM_AARCH64 != ehdr->e_machine) return -1;
#elif defined(__i386__)
    if(EM_386 != ehdr->e_machine) return -1;
#elif defined(__x86_64__)
    if(EM_X86_64 != ehdr->e_machine) return -1;
#else
    return -1;
#endif

    //check version
    if(EV_CURRENT != ehdr->e_version) return -1;

    return 0;
}

static int xh_core_check_elf_header(uintptr_t base_addr, const char *pathname)
{
    if(!xh_core_sigsegv_enable)
    {
        return xh_elf_check_elfheader(base_addr);
    }
    else
    {
        int ret = -1;

        xh_core_sigsegv_flag = 1;
        if(0 == sigsetjmp(xh_core_sigsegv_env, 1))
        {
            ret = xh_elf_check_elfheader(base_addr);
        }
        else
        {
            ret = -1;
            LOG_WARN("catch SIGSEGV when check_elfheader: %s", pathname);
        }
        xh_core_sigsegv_flag = 0;
        return ret;
    }
}

static int xh_single_so_search_iterate_cb(struct dl_phdr_info* info, size_t info_size, void* data) {
    xh_single_so_iterate_args_t* args = (xh_single_so_iterate_args_t*)data;
    const char* pathname = info->dlpi_name;
    size_t path_len = strlen(pathname);
    size_t path_suffix_len = strlen(args->path_suffix);
    if (strncmp(pathname + path_len - path_suffix_len, args->path_suffix, path_suffix_len) != 0) {
        return 0;
    }
    int check_elf_ret = xh_core_check_elf_header(info->dlpi_addr, pathname);
    if (0 != check_elf_ret) {
        LOG_ERROR("check elf header header: %s failed, ret: %d", pathname, check_elf_ret);
        return 0;
    }
    args->mi->pathname = strdup(pathname);
    if (args->mi->pathname == NULL) {
        LOG_ERROR("Fail to strdup of copy path: %s", pathname);
        return -1;
    }
    args->mi->bias_addr = info->dlpi_addr;
    args->mi->phdrs = (ElfW(Phdr)*)info->dlpi_phdr;
    args->mi->phdr_count = info->dlpi_phnum;
    return 1;
}

void* open_elf_file(const char* path) {
    if (path == NULL) {
        LOG_ERROR("path is NULL");
        return NULL;
    }
    xh_core_map_info_t* mi = malloc(sizeof(xh_core_map_info_t));
    if (mi == NULL) {
        LOG_ERROR("allocate memory failed");
        return NULL;
    }
    memset(mi, 0, sizeof(xh_core_map_info_t));
    
    xh_single_so_iterate_args_t iter_args = {
        .path_suffix = path,
        .mi = mi
    };
    int iter_ret = semi_dl_iterate_phdr(xh_single_so_search_iterate_cb, &iter_args);
    if (iter_ret > 0) {
        LOG_INFO("open so with path %s successfully, realpath: %s", path, mi->pathname);
        return mi;
    } else {
        if (mi->pathname != NULL) {
            free(mi->pathname);
            mi->pathname = NULL;
        }
        free(mi);
        LOG_ERROR("open %s failed", path);
        return NULL;
    }
}

int do_hook_symbol(void* h_lib, const char* symbol, void* new_func, void** old_func) {
    if (h_lib == NULL || symbol == NULL || new_func == NULL) {
        LOG_ERROR("input param is invalid");
        return -1;
    }
    xh_core_map_info_t* mi = (xh_core_map_info_t*)h_lib;
    int ret = xh_elf_init(&(mi->elf), mi->bias_addr, mi->phdrs, mi->phdr_count, mi->pathname);
    if (ret != 0) {
        return ret;
    }
    return xh_elf_hook(&(mi->elf), symbol, new_func, old_func);
}

void close_elf_file(void* h_lib) {
    if (h_lib == NULL) return;

    xh_core_map_info_t* mi = h_lib;
    if (mi->pathname != NULL) {
        free(mi->pathname);
    }
    free(mi);
}