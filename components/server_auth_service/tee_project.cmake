# Must be included in the project's top-level CMakeLists.txt BEFORE project()
# Registers the server_auth_service custom TEE secure service with the build system

get_filename_component(directory "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE DIRECTORY)
get_filename_component(name ${CMAKE_CURRENT_LIST_DIR} NAME)

idf_build_set_property(CUSTOM_SECURE_SERVICE_YAML ${CMAKE_CURRENT_LIST_DIR}/sec_srv_tbl_server_auth.yml APPEND)
idf_build_set_property(CUSTOM_SECURE_SERVICE_COMPONENT_DIR ${directory} APPEND)
idf_build_set_property(CUSTOM_SECURE_SERVICE_COMPONENT ${name} APPEND)
