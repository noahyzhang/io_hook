#include <fcntl.h>

namespace io_hook {

extern "C" {

int ProxyOpen(const char* pathname, int flags, mode_t mode);

void do_hook();

}  // extern "C"

}  // namespace io_hook
