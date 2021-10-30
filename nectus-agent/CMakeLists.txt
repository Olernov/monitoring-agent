project(nectus-agent)
cmake_minimum_required(VERSION 3.9)
# Set a default build type if none was specified
set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
      STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++11 -Wall")

SET(Boost_USE_STATIC_LIBS       ON)
SET(Boost_USE_STATIC_RUNTIME    ON)
find_package(Boost 1.66 COMPONENTS system filesystem regex REQUIRED)

SET(Protobuf_USE_STATIC_LIBS    ON)
find_package(Protobuf REQUIRED)

find_package(OpenSSL REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/../Common ${PROJECT_SOURCE_DIR}/../3rdParty/spdlog)


# TODO: add .proto file compilation?

aux_source_directory(${PROJECT_SOURCE_DIR}/../Common SRC_LIST)
aux_source_directory(${PROJECT_SOURCE_DIR}/../3rdParty SRC_LIST)
aux_source_directory(${PROJECT_SOURCE_DIR}/src SRC_LIST)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS monitoring.proto)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries (${PROJECT_NAME} ${PROTOBUF_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_ASIO_LIBRARY} ${Boost_REGEX_LIBRARY}
    ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY}
    )

install (
        FILES "${PROJECT_NAME}"
        DESTINATION "/usr/bin"
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ
)
