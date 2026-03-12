cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Register the server_auth_service with the TEE build (must be BEFORE project())
include(${CMAKE_CURRENT_LIST_DIR}/components/server_auth_service/tee_project.cmake)

idf_build_set_property(MINIMAL_BUILD ON)
project(tee_server_auth)
