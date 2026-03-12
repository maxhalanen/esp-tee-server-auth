cmake_minimum_required(VERSION 3.22)

idf_build_get_property(esp_tee_build ESP_TEE_BUILD)

set(srcs)
set(include_dirs include)

if(esp_tee_build)
    # TEE build: compile the service implementation into M-mode
    list(APPEND srcs "server_auth_service.c")
endif()

# Expose the shared header to both TEE and REE builds
idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${include_dirs}
                       PRIV_REQUIRES main)
