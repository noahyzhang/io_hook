#ifndef LOG_H_
#define LOG_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_DEBUG(fmt, ...) do{ printf("[%s:%d->%s %s] " fmt "\n", __FILE__, __LINE__, __func__, "DEBUG", ##__VA_ARGS__); }while(0)
#define LOG_INFO(fmt, ...) do{ printf("[%s:%d->%s %s] " fmt "\n", __FILE__, __LINE__, __func__, "INFO", ##__VA_ARGS__); }while(0)
#define LOG_WARN(fmt, ...) do{ printf("[%s:%d->%s %s] " fmt "\n", __FILE__, __LINE__, __func__, "WARN", ##__VA_ARGS__); }while(0)
#define LOG_ERROR(fmt, ...) do{ printf("[%s:%d->%s %s] " fmt "\n", __FILE__, __LINE__, __func__, "ERROR", ##__VA_ARGS__); }while(0)

#ifdef __cplusplus
}
#endif

#endif  // LOG_H_
