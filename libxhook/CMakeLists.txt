cmake_minimum_required(VERSION 3.10.2)
project(libxhook C)

add_definitions(-w)

set(xhook_source_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(
  xhook_source
  ${xhook_source_dir}/semi_dlfcn.c
  ${xhook_source_dir}/xh_elf.c
  ${xhook_source_dir}/xh_maps.c
  ${xhook_source_dir}/xh_util.c
  ${xhook_source_dir}/xhook_core.c
)

add_library(xhook STATIC ${xhook_source})

target_include_directories(
  xhook
  PUBLIC ${xhook_source_dir}
)

target_link_libraries(
    xhook
    pthread
    dl
)