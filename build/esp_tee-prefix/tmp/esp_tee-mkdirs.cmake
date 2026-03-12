# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/max/esp/esp-idf/components/esp_tee/subproject"
  "/home/max/esp/tee_server_auth/build/esp_tee"
  "/home/max/esp/tee_server_auth/build/esp_tee-prefix"
  "/home/max/esp/tee_server_auth/build/esp_tee-prefix/tmp"
  "/home/max/esp/tee_server_auth/build/esp_tee-prefix/src/esp_tee-stamp"
  "/home/max/esp/tee_server_auth/build/esp_tee-prefix/src"
  "/home/max/esp/tee_server_auth/build/esp_tee-prefix/src/esp_tee-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/max/esp/tee_server_auth/build/esp_tee-prefix/src/esp_tee-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/max/esp/tee_server_auth/build/esp_tee-prefix/src/esp_tee-stamp${cfgdir}") # cfgdir has leading slash
endif()
