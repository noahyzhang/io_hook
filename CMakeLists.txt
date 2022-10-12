cmake_minimum_required(VERSION 3.10.2)
project(io_hook)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

add_subdirectory(libxhook)

set(io_hook_source_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(
        io_hook_source
        ${io_hook_source_dir}/io_hook.cpp
        ${io_hook_source_dir}/main.cpp
)

add_executable(io_hook ${io_hook_source})

target_include_directories(
        io_hook
        PUBLIC ${io_hook_source_dir}
        PUBLIC ${io_hook_source_dir}/libxhook
)

target_link_libraries(
        io_hook
        PUBLIC xhook
)

