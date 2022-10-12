#ifndef HOOK_CORE_H_
#define HOOK_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

// 打开 elf 文件
void* open_elf_file(const char* path);

// 使用新函数去 hook 替换旧函数
int do_hook_symbol(void* h_lib, const char* symbol, void* new_func, void** old_func);

// 关闭 elf 文件
void close_elf_file(void* h_lib);

#ifdef __cplusplus
}
#endif

#endif // HOOK_CORE_H_
