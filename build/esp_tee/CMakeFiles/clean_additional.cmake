# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "")
  file(REMOVE_RECURSE
  "config/sdkconfig.cmake"
  "config/sdkconfig.h"
  "esp_tee.bin"
  "esp_tee.map"
  "project_elf_src_esp32c6.c"
  )
endif()
