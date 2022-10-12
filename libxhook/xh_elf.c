#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "xh_elf.h"
#include "xh_log.h"
#include "xh_util.h"

#ifndef EI_ABIVERSION
#define EI_ABIVERSION 8
#endif

#if defined(__arm__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define XH_ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define XH_ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_X86_64_64
#endif

#if defined(__LP64__)
#define XH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define XH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

//iterator for plain PLT
typedef struct
{
    uint8_t  *cur;
    uint8_t  *end;
    int       is_use_rela;
} xh_elf_plain_reloc_iterator_t;

static void xh_elf_plain_reloc_iterator_init(xh_elf_plain_reloc_iterator_t *self,
                                             ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela)
{
    self->cur = (uint8_t *)rel;
    self->end = self->cur + rel_sz;
    self->is_use_rela = is_use_rela;
}

static void *xh_elf_plain_reloc_iterator_next(xh_elf_plain_reloc_iterator_t *self)
{
    if(self->cur >= self->end) return NULL;

    void *ret = (void *)(self->cur);
    self->cur += (self->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
    return ret;
}

//sleb128 decoder
typedef struct
{
    uint8_t  *cur;
    uint8_t  *end;
} xh_elf_sleb128_decoder_t;

//iterator for sleb128 decoded packed PLT
typedef struct
{
    xh_elf_sleb128_decoder_t decoder;
    size_t                   relocation_count;
    size_t                   group_size;
    size_t                   group_flags;
    size_t                   group_r_offset_delta;
    size_t                   relocation_index;
    size_t                   relocation_group_index;
    ElfW(Rela)               rela;
    ElfW(Rel)                rel;
    ElfW(Addr)               r_offset;
    size_t                   r_info;
    ssize_t                  r_addend;
    int                      is_use_rela;
} xh_elf_packed_reloc_iterator_t;

static int xh_elf_replace_function(xh_elf_t *self, const char *symbol, ElfW(Addr) addr, void *new_func, void **old_func)
{
    void         *old_addr;
    unsigned int  old_prot = 0;
    unsigned int  need_prot = PROT_READ | PROT_WRITE;
    int           r;

    //already replaced?
    //here we assume that we always have read permission, is this a problem?
    if(*(void **)addr == new_func) return 0;

    //get old prot
    if(0 != (r = xh_util_get_addr_protect(addr, self->pathname, &old_prot)))
    {
        LOG_ERROR("get addr prot failed. ret: %d", r);
        return r;
    }

    // if(old_prot != need_prot)
    // {
        //set new prot
        if(0 != (r = xh_util_set_addr_protect(addr, need_prot)))
        {
            LOG_ERROR("set addr prot failed. ret: %d", r);
            return r;
        }
    // }

    //save old func
    old_addr = *(void **)addr;
    if(NULL != old_func) *old_func = old_addr;

    //replace func
    // *(void **)addr = new_func; //segmentation fault sometimes
    void* new_func_addr = (void*) new_func;
    ssize_t got_write_ret = xh_util_write_memory_safely((void*) addr, (uint8_t*) &new_func_addr, sizeof(void*));
    if (got_write_ret != sizeof(void*))
    {
        LOG_ERROR("Fail to write new address into GOT/Data item, dest_address: %p", (const void*) addr);
        return -1;
    }

    // if(old_prot != need_prot)
    // {
        if ((old_prot & PROT_READ) == 0) {
            LOG_WARN("old addr has no read permission, it's not usual and may cause segment fault.");
            old_prot |= PROT_READ;
        }
        //restore the old prot
        if(0 != (r = xh_util_set_addr_protect(addr, old_prot)))
        {
            LOG_WARN("restore addr prot failed. ret: %d", r);
        }
    // }

    //clear cache
    xh_util_flush_instruction_cache(addr);

    LOG_INFO("XH_HK_OK %p: %p -> %p %s %s\n", (void *)addr, old_addr, new_func, symbol, self->pathname);
    return 0;
}

static int xh_elf_check(xh_elf_t *self) {
    if(0 == self->base_addr) {
        LOG_DEBUG("base_addr == 0\n");
        return 1;
    }
    if(0 == self->bias_addr) {
        LOG_DEBUG("bias_addr == 0\n");
        return 1;
    }
    if(NULL == self->ehdr) {
        LOG_DEBUG("ehdr == NULL\n");
        return 1;
    }
    if(NULL == self->phdr) {
        LOG_DEBUG("phdr == NULL\n");
        return 1;
    }
    if(NULL == self->strtab) {
        LOG_DEBUG("strtab == NULL\n");
        return 1;
    }
    if(NULL == self->symtab) {
        LOG_DEBUG("symtab == NULL\n");
        return 1;
    }
    if(NULL == self->bucket) {
        LOG_DEBUG("bucket == NULL\n");
        return 1;
    }
    if(NULL == self->chain) {
        LOG_DEBUG("chain == NULL\n");
        return 1;
    }
    if(1 == self->is_use_gnu_hash && NULL == self->bloom) {
        LOG_DEBUG("bloom == NULL\n");
        return 1;
    }
    return 0;
}

static void xh_elf_dump_elfheader(xh_elf_t *self)
{
    static char alpha_tab[17] = "0123456789ABCDEF";
    int         i;
    uint8_t     ch;
    char        buff[EI_NIDENT * 3 + 1];

    for(i = 0; i < EI_NIDENT; i++)
    {
        ch = self->ehdr->e_ident[i];
        buff[i * 3 + 0] = alpha_tab[(int)((ch >> 4) & 0x0F)];
        buff[i * 3 + 1] = alpha_tab[(int)(ch & 0x0F)];
        buff[i * 3 + 2] = ' ';
    }
    buff[EI_NIDENT * 3] = '\0';

    LOG_DEBUG("Elf Header:\n");
    LOG_DEBUG("  Magic:                             %s\n",                                 buff);
    LOG_DEBUG("  Class:                             %#x\n",                                self->ehdr->e_ident[EI_CLASS]);
    LOG_DEBUG("  Data:                              %#x\n",                                self->ehdr->e_ident[EI_DATA]);
    LOG_DEBUG("  Version:                           %#x\n",                                self->ehdr->e_ident[EI_VERSION]);
    LOG_DEBUG("  OS/ABI:                            %#x\n",                                self->ehdr->e_ident[EI_OSABI]);
    LOG_DEBUG("  ABI Version:                       %#x\n",                                self->ehdr->e_ident[EI_ABIVERSION]);
    LOG_DEBUG("  Type:                              %#x\n",                                self->ehdr->e_type);
    LOG_DEBUG("  Machine:                           %#x\n",                                self->ehdr->e_machine);
    LOG_DEBUG("  Version:                           %#x\n",                                self->ehdr->e_version);
    LOG_DEBUG("  Entry point address:               %"XH_UTIL_FMT_X"\n",                   self->ehdr->e_entry);
    LOG_DEBUG("  Start of program headers:          %"XH_UTIL_FMT_X" (bytes into file)\n", self->ehdr->e_phoff);
    LOG_DEBUG("  Start of section headers:          %"XH_UTIL_FMT_X" (bytes into file)\n", self->ehdr->e_shoff);
    LOG_DEBUG("  Flags:                             %#x\n",                                self->ehdr->e_flags);
    LOG_DEBUG("  Size of this header:               %u (bytes)\n",                         self->ehdr->e_ehsize);
    LOG_DEBUG("  Size of program headers:           %u (bytes)\n",                         self->ehdr->e_phentsize);
    LOG_DEBUG("  Number of program headers:         %u\n",                                 self->ehdr->e_phnum);
    LOG_DEBUG("  Size of section headers:           %u (bytes)\n",                         self->ehdr->e_shentsize);
    LOG_DEBUG("  Number of section headers:         %u\n",                                 self->ehdr->e_shnum);
    LOG_DEBUG("  Section header string table index: %u\n",                                 self->ehdr->e_shstrndx);
}

static void xh_elf_dump_programheader(xh_elf_t *self)
{
    ElfW(Phdr) *phdr = self->phdr;
    size_t i;

    LOG_DEBUG("Program Headers:\n");
    LOG_DEBUG("  %-8s " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-8s " \
                 "%-s\n",
                 "Type",
                 "Offset",
                 "VirtAddr",
                 "PhysAddr",
                 "FileSiz",
                 "MemSiz",
                 "Flg",
                 "Align");
    for(i = 0; i < self->ehdr->e_phnum; i++, phdr++)
    {
        LOG_DEBUG("  %-8x " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%-8x " \
                     "%"XH_UTIL_FMT_X"\n",
                     phdr->p_type,
                     phdr->p_offset,
                     phdr->p_vaddr,
                     phdr->p_paddr,
                     phdr->p_filesz,
                     phdr->p_memsz,
                     phdr->p_flags,
                     phdr->p_align);
    }
}

static void xh_elf_dump_dynamic(xh_elf_t *self)
{
    ElfW(Dyn) *dyn = self->dyn;
    size_t     dyn_cnt = (self->dyn_sz / sizeof(ElfW(Dyn)));
    size_t     i;

    LOG_DEBUG("Dynamic section contains %zu entries:\n", dyn_cnt);
    LOG_DEBUG("  %-"XH_UTIL_FMT_FIXED_S" " \
                 "%s\n",
                 "Tag",
                 "Val");
    for(i = 0; i < dyn_cnt; i++, dyn++)
    {
        LOG_DEBUG("  %-"XH_UTIL_FMT_FIXED_X" " \
                     "%-"XH_UTIL_FMT_X"\n",
                     dyn->d_tag,
                     dyn->d_un.d_val);
    }
}

static void xh_elf_dump_rel(xh_elf_t *self, const char *type, ElfW(Addr) rel_addr, ElfW(Word) rel_sz)
{
    ElfW(Rela) *rela;
    ElfW(Rel)  *rel;
    ElfW(Word)  cnt;
    ElfW(Word)  i;
    ElfW(Sym)  *sym;

    if(self->is_use_rela)
    {
        rela = (ElfW(Rela) *)(rel_addr);
        cnt  = rel_sz / sizeof(ElfW(Rela));
    }
    else
    {
        rel = (ElfW(Rel) *)(rel_addr);
        cnt = rel_sz / sizeof(ElfW(Rel));
    }

    LOG_DEBUG("Relocation section '.rel%s%s' contains %u entries:\n",
                 (self->is_use_rela ? "a" : ""), type, cnt);
    LOG_DEBUG("  %-"XH_UTIL_FMT_FIXED_S" " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%-8s " \
                 "%-8s " \
                 "%-8s " \
                 "%s\n",
                 "Offset",
                 "Info",
                 "Type",
                 "Sym.Idx",
                 "Sym.Val",
                 "Sym.Name");
    const char *fmt = "  %."XH_UTIL_FMT_FIXED_X" " \
                      "%."XH_UTIL_FMT_FIXED_X" " \
                      "%.8x " \
                      "%.8u " \
                      "%.8x " \
                      "%s\n";
    for(i = 0; i < cnt; i++)
    {
        if(self->is_use_rela)
        {
            sym = &(self->symtab[XH_ELF_R_SYM(rela[i].r_info)]);
            // LOG_DEBUG((fmt),
            //              rela[i].r_offset,
            //              rela[i].r_info,
            //              XH_ELF_R_TYPE(rela[i].r_info),
            //              XH_ELF_R_SYM(rela[i].r_info),
            //              sym->st_value,
            //              self->strtab + sym->st_name);
        }
        else
        {
            sym = &(self->symtab[XH_ELF_R_SYM(rel[i].r_info)]);
            // LOG_DEBUG(fmt,
            //              rel[i].r_offset,
            //              rel[i].r_info,
            //              XH_ELF_R_TYPE(rel[i].r_info),
            //              XH_ELF_R_SYM(rel[i].r_info),
            //              sym->st_value,
            //              self->strtab + sym->st_name);
        }
    }
}

static void xh_elf_dump_symtab(xh_elf_t *self)
{
    if(self->is_use_gnu_hash) return;

    ElfW(Word)  symtab_cnt = self->chain_cnt;
    ElfW(Word)  i;

    LOG_DEBUG("Symbol table '.dynsym' contains %u entries:\n", symtab_cnt);
    LOG_DEBUG("  %-8s " \
                 "%-"XH_UTIL_FMT_FIXED_S" " \
                 "%s\n",
                 "Idx",
                 "Value",
                 "Name");
    for(i = 0; i < symtab_cnt; i++)
    {
        LOG_DEBUG("  %-8u " \
                     "%."XH_UTIL_FMT_FIXED_X" " \
                     "%s\n",
                     i,
                     self->symtab[i].st_value,
                     self->strtab + self->symtab[i].st_name);
    }
}

static void xh_elf_dump(xh_elf_t *self) {

    LOG_DEBUG("Elf Pathname: %s\n", self->pathname);
    LOG_DEBUG("Elf bias addr: %p\n", (void *)self->bias_addr);
    xh_elf_dump_elfheader(self);
    xh_elf_dump_programheader(self);
    xh_elf_dump_dynamic(self);
    xh_elf_dump_rel(self, ".plt", self->relplt, self->relplt_sz);
    xh_elf_dump_rel(self, ".dyn", self->reldyn, self->reldyn_sz);
    xh_elf_dump_symtab(self);
}

//ELF hash func
static uint32_t xh_elf_hash(const uint8_t *name)
{
    uint32_t h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }

    return h;
}

//GNU hash func
static uint32_t xh_elf_gnu_hash(const uint8_t *name)
{
    uint32_t h = 5381;

    while(*name != 0)
    {
        h += (h << 5) + *name++;
    }
    return h;
}

static ElfW(Phdr) *xh_elf_get_first_segment_by_type(xh_elf_t *self, ElfW(Word) type)
{
    ElfW(Phdr) *phdr;

    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++)
    {
        if(phdr->p_type == type)
        {
            return phdr;
        }
    }
    return NULL;
}

static ElfW(Phdr) *xh_elf_get_first_segment_by_type_offset(xh_elf_t *self, ElfW(Word) type, ElfW(Off) offset)
{
    ElfW(Phdr) *phdr;

    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++)
    {
        if(phdr->p_type == type && phdr->p_offset == offset)
        {
            return phdr;
        }
    }
    return NULL;
}

static int xh_elf_hash_lookup(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    uint32_t    hash = xh_elf_hash((uint8_t *)symbol);
    const char *symbol_cur;
    uint32_t    i;

    for(i = self->bucket[hash % self->bucket_cnt]; 0 != i; i = self->chain[i])
    {
        symbol_cur = self->strtab + self->symtab[i].st_name;

        if(0 == strcmp(symbol, symbol_cur))
        {
            *symidx = i;
            LOG_INFO("found %s at symidx: %u (ELF_HASH)\n", symbol, *symidx);
            return 0;
        }
    }

    return -1;
}

static int xh_elf_gnu_hash_lookup_def(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    uint32_t hash = xh_elf_gnu_hash((uint8_t *)symbol);

    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = self->bloom[(hash / elfclass_bits) % self->bloom_sz];
    size_t mask = 0
                  | (size_t)1 << (hash % elfclass_bits)
                  | (size_t)1 << ((hash >> self->bloom_shift) % elfclass_bits);

    //if at least one bit is not set, this symbol is surely missing
    if((word & mask) != mask) return -1;

    //ignore STN_UNDEF
    uint32_t i = self->bucket[hash % self->bucket_cnt];
    if(i < self->symoffset) return -1;

    //loop through the chain
    while(1)
    {
        const char     *symname = self->strtab + self->symtab[i].st_name;
        const uint32_t  symhash = self->chain[i - self->symoffset];

        if((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname))
        {
            *symidx = i;
            LOG_INFO("found %s at symidx: %u (GNU_HASH DEF)\n", symbol, *symidx);
            return 0;
        }

        //chain ends with an element with the lowest bit set to 1
        if(symhash & (uint32_t)1) break;

        i++;
    }

    return -2;
}

static int xh_elf_gnu_hash_lookup_undef(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    uint32_t i;

    for(i = 0; i < self->symoffset; i++)
    {
        const char *symname = self->strtab + self->symtab[i].st_name;
        if(0 == strcmp(symname, symbol))
        {
            *symidx = i;
            LOG_INFO("found %s at symidx: %u (GNU_HASH UNDEF)\n", symbol, *symidx);
            return 0;
        }
    }
    return -1;
}

static int xh_elf_gnu_hash_lookup(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    if(0 == xh_elf_gnu_hash_lookup_def(self, symbol, symidx)) return 0;
    if(0 == xh_elf_gnu_hash_lookup_undef(self, symbol, symidx)) return 0;
    return -1;
}


int xh_elf_find_symidx_by_name(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    int ret = 0;
    if(self->is_use_gnu_hash)
        ret = xh_elf_gnu_hash_lookup(self, symbol, symidx);
    else
        ret = xh_elf_hash_lookup(self, symbol, symidx);

    return ret;
}

int xh_elf_init(xh_elf_t *self, uintptr_t bias_addr, ElfW(Phdr)* phdrs, ElfW(Half) phdr_count, const char *pathname) {
    if (0 == bias_addr || NULL == pathname) {
        LOG_ERROR("input param is invalid");
        return -1;
    }
    memset(self, 0, sizeof(xh_elf_t));
    self->pathname = pathname;
    self->bias_addr = (ElfW(Addr))bias_addr;
    self->phdr = phdrs;
    LOG_DEBUG("xh_elf_init: pathname: %s, phdr: %p, phdr_count: %u", pathname, phdrs, phdr_count);

    ElfW(Phdr)* phdr0 = NULL;
    for (int i = 0;i < phdr_count; ++i) {
        ElfW(Phdr)* phdr = phdrs + i;
        if (phdr->p_type == PT_LOAD) {
            phdr0 = phdr;
            break;
        }
    }
    if (NULL == phdr0) {
        LOG_ERROR("can not found the first load segment of pathname: %s", pathname);
        return -2;
    }
    self->base_addr = self->bias_addr + phdr0->p_vaddr;
    if (self->base_addr < phdr0->p_vaddr) {
        LOG_ERROR("elf file is not format file");
        return -3;
    }
    // 寻找 dynamic-segment
    ElfW(Phdr)* dhdr = xh_elf_get_first_segment_by_type(self, PT_DYNAMIC);
    if (NULL == dhdr) {
        LOG_ERROR("can not found dynamic segment of pathname: %s", pathname);
        return -4;
    }
     // 解析 dynamic-segment
    self->dyn          = (ElfW(Dyn) *)(self->bias_addr + dhdr->p_vaddr);
    self->dyn_sz       = dhdr->p_memsz;
    ElfW(Dyn) *dyn     = self->dyn;
    ElfW(Dyn) *dyn_end = self->dyn + (self->dyn_sz / sizeof(ElfW(Dyn)));
    uint32_t  *raw;
    for(; dyn < dyn_end; dyn++)
    {
        switch(dyn->d_tag) //segmentation fault sometimes
        {
            case DT_NULL:
                //the end of the dynamic-section
                dyn = dyn_end;
                break;
            case DT_STRTAB:
            {
                self->strtab = (const char *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->strtab) < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                break;
            }
            case DT_SYMTAB:
            {
                self->symtab = (ElfW(Sym) *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->symtab) < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                break;
            }
            case DT_PLTREL:
                //use rel or rela?
                self->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
                break;
            case DT_JMPREL:
            {
                self->relplt = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->relplt) < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                break;
            }
            case DT_PLTRELSZ:
                self->relplt_sz = dyn->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELA:
            {
                self->reldyn = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->reldyn) < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                break;
            }
            case DT_RELSZ:
            case DT_RELASZ:
                self->reldyn_sz = dyn->d_un.d_val;
                break;
            case DT_HASH:
            {
                //ignore DT_HASH when ELF contains DT_GNU_HASH hash table
                if(1 == self->is_use_gnu_hash) continue;

                raw = (uint32_t *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))raw < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                self->bucket_cnt  = raw[0];
                self->chain_cnt   = raw[1];
                self->bucket      = &raw[2];
                self->chain       = &(self->bucket[self->bucket_cnt]);
                break;
            }
            case DT_GNU_HASH:
            {
                raw = (uint32_t *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))raw < self->base_addr) {
                    LOG_ERROR("elf file is not format file");
                    return -3;
                }
                self->bucket_cnt  = raw[0];
                self->symoffset   = raw[1];
                self->bloom_sz    = raw[2];
                self->bloom_shift = raw[3];
                self->bloom       = (ElfW(Addr) *)(&raw[4]);
                self->bucket      = (uint32_t *)(&(self->bloom[self->bloom_sz]));
                self->chain       = (uint32_t *)(&(self->bucket[self->bucket_cnt]));
                self->is_use_gnu_hash = 1;
                break;
            }
            default:
                break;
        }
    }

    //check elf info
    if(0 != xh_elf_check(self))
    {
        LOG_ERROR("elf init check failed. %s", pathname);
        return -3;
    }

    xh_elf_dump(self);

    LOG_INFO("init OK: %s (%s %s PLT:%u DYN:%u )\n", self->pathname,
                self->is_use_rela ? "RELA" : "REL",
                self->is_use_gnu_hash ? "GNU_HASH" : "ELF_HASH",
                self->relplt_sz, self->reldyn_sz);

    return 0;
}

static int xh_elf_find_and_replace_func(xh_elf_t *self, const char *section,
                                        int is_plt, const char *symbol,
                                        void *new_func, void **old_func,
                                        uint32_t symidx, void *rel_common,
                                        int *found)
{
    ElfW(Rela)    *rela;
    ElfW(Rel)     *rel;
    ElfW(Addr)     r_offset;
    size_t         r_info;
    size_t         r_sym;
    size_t         r_type;
    ElfW(Addr)     addr;
    int            r;

    if(NULL != found) *found = 0;

    if(self->is_use_rela)
    {
        rela = (ElfW(Rela) *)rel_common;
        r_info = rela->r_info;
        r_offset = rela->r_offset;
    }
    else
    {
        rel = (ElfW(Rel) *)rel_common;
        r_info = rel->r_info;
        r_offset = rel->r_offset;
    }

    //check sym
    r_sym = XH_ELF_R_SYM(r_info);

    // modified: fix
    if(r_sym != symidx) return 0;

    //check type
    r_type = XH_ELF_R_TYPE(r_info);
    if(is_plt && r_type != XH_ELF_R_GENERIC_JUMP_SLOT) return 0;
    if(!is_plt && (r_type != XH_ELF_R_GENERIC_GLOB_DAT && r_type != XH_ELF_R_GENERIC_ABS)) return 0;

    //we found it
    LOG_INFO("found %s at %s offset: %p\n", symbol, section, (void *)r_offset);
    if(NULL != found) *found = 1;

    //do replace
    addr = self->bias_addr + r_offset;
    if(addr < self->base_addr) return -1;
    if(0 != (r = xh_elf_replace_function(self, symbol, addr, new_func, old_func)))
    {
        LOG_ERROR("replace function failed: %s at %s\n", symbol, section);
        return r;
    }

    return 0;
}

int xh_elf_hook(xh_elf_t *self, const char *symbol, void *new_func, void **old_func)
{
    uint32_t                        symidx;
    void                           *rel_common;
    xh_elf_plain_reloc_iterator_t   plain_iter;
    xh_elf_packed_reloc_iterator_t  packed_iter;
    int                             found;
    int                             r;

    if(NULL == self->pathname)
    {
        LOG_ERROR("not inited\n");
        return -1;
    }

    if(NULL == symbol || NULL == new_func) {
        LOG_ERROR("param invalid");
        return -2;
    }

    LOG_INFO("hooking %s in %s\n", symbol, self->pathname);

    //find symbol index by symbol name
    if(0 != (r = xh_elf_find_symidx_by_name(self, symbol, &symidx))) {
        return r;
    }

    //replace for .rel(a).plt
    if(0 != self->relplt)
    {
        xh_elf_plain_reloc_iterator_init(&plain_iter, self->relplt, self->relplt_sz, self->is_use_rela);
        found = 0;
        while(NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter)))
        {
            if(0 != (r = xh_elf_find_and_replace_func(self,
                                                      (self->is_use_rela ? ".rela.plt" : ".rel.plt"), 1,
                                                      symbol, new_func, old_func,
                                                      symidx, rel_common, &found))) return r;
            if (found) break;
        }
    }

    //replace for .rel(a).dyn
    if(0 != self->reldyn)
    {
        xh_elf_plain_reloc_iterator_init(&plain_iter, self->reldyn, self->reldyn_sz, self->is_use_rela);
        while(NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter)))
        {
            if(0 != (r = xh_elf_find_and_replace_func(self,
                                                      (self->is_use_rela ? ".rela.dyn" : ".rel.dyn"), 0,
                                                      symbol, new_func, old_func,
                                                      symidx, rel_common, &found))) return r;
        }
    }

    return 0;
}
