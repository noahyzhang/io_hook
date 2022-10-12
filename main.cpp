#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "io_hook.h"

int main() {
    io_hook::do_hook();

    int fd = open("./test.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        std::cout << "open file failed, errno: " << errno << ", errstr: " << strerror(errno) << std::endl;
        return -1;
    }
    char input_buf[] = "hello world";
    auto res = write(fd, input_buf, sizeof(input_buf));
    if (res < 0) {
        std::cout << "write failed, errno: " << errno << ", errstr: " << strerror(errno) << std::endl;
        return -2;
    }
    res = lseek(fd, 0, SEEK_SET);
    if (res < 0) {
        std::cout << "lseek failed, errno: " << errno << ", errstr: " << strerror(errno) << std::endl;
        return -3;
    }

    char output_buf[100];
    res = read(fd, output_buf, sizeof(output_buf));
    if (res < 0) {
        std::cout << "read failed, errno: " << errno << ", errstr: " << strerror(errno) << std::endl;
        return -4;
    }
    output_buf[res] = '\0';
    std::cout << output_buf << std::endl;
    close(fd);
    return 0;
}
