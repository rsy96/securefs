cmake_minimum_required(VERSION 3.7 FATAL_ERROR)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()

option(SECUREFS_USE_FUSET
       "Use FUSE-T instead of MacFUSE (only makes sense on macOS)" OFF)
set(SECUREFS_WINFSP_LOCATION
    "C:/Program Files (x86)/WinFsp"
    CACHE PATH "Location of the WinFsp installation directory")

project(securefs)
enable_testing()

set(CMAKE_FIND_FRAMEWORK NEVER)

if(APPLE)
    add_link_options(-Wl,-dead_strip)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wthread-safety)
    if(MINGW)
        add_compile_options(-fansi-escape-codes -fcolor-diagnostics)
    endif()
endif()

file(GLOB CORE_SOURCES sources/core/*.hpp sources/core/*.cpp protos/*.proto)
add_library(securefs-core STATIC ${CORE_SOURCES})
target_compile_definitions(securefs-core PRIVATE _CRT_NONSTDC_NO_WARNINGS=1)

find_package(Threads)
find_package(cryptopp)
find_package(absl)
find_package(doctest)
find_package(SQLite3)
find_package(Protobuf)
find_package(unofficial-utf8proc)
find_package(Boost)
find_package(magic_enum)
find_package(unofficial-argon2)
find_package(blake3)
target_link_libraries(
    securefs-core
    PUBLIC Threads::Threads
           cryptopp::cryptopp
           BLAKE3::blake3
           absl::base
           absl::endian
           absl::cleanup
           absl::span
           absl::str_format
           absl::strings
           absl::synchronization
           absl::log
           absl::log_globals
           absl::log_initialize
           absl::log_sink
           absl::log_sink_registry
           protobuf::libprotobuf
           SQLite::SQLite3
           utf8proc
           Boost::boost
           magic_enum::magic_enum
           unofficial::argon2::libargon2)
protobuf_generate(TARGET securefs-core IMPORT_DIRS protos PROTOC_OUT_DIR
                  ${CMAKE_CURRENT_BINARY_DIR}/out/)
target_include_directories(securefs-core
                           PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/out/)

find_package(CLI11)
file(GLOB MAIN_SOURCES sources/main/*.hpp sources/main/*.cpp)
add_library(securefs-main STATIC ${MAIN_SOURCES})
target_link_libraries(securefs-main PUBLIC securefs-core CLI11::CLI11)
target_include_directories(securefs-main PUBLIC sources)
target_compile_definitions(securefs-main PRIVATE _CRT_NONSTDC_NO_WARNINGS=1)

file(
    GLOB
    TEST_CORE_SOURCES
    test/core/*.hpp
    test/core/*.cpp
    test/main/*.cpp
    test/main/*.hpp
    test/test_main.cpp)
add_executable(securefs-test ${TEST_CORE_SOURCES})
find_package(doctest REQUIRED)
target_link_libraries(securefs-test PRIVATE securefs-core securefs-main
                                            doctest::doctest)
target_compile_definitions(securefs-test PRIVATE _CRT_NONSTDC_NO_WARNINGS=1)

add_test(
    NAME securefs-test
    COMMAND securefs-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

if(CMAKE_DL_LIBS)
    target_link_libraries(securefs-core PUBLIC ${CMAKE_DL_LIBS})
endif()

add_executable(securefs main.cpp)

if(WIN32)
    target_sources(securefs PRIVATE securefs.manifest)
    target_sources(securefs-test PRIVATE securefs.manifest)
    target_include_directories(securefs-main SYSTEM
                               PUBLIC ${SECUREFS_WINFSP_LOCATION}/inc)
    target_link_libraries(
        securefs-main
        PUBLIC ${SECUREFS_WINFSP_LOCATION}/lib/winfsp-x64.lib
        PUBLIC delayimp.lib)
    target_link_options(securefs-main PUBLIC -DELAYLOAD:winfsp-x64.dll)
endif()

target_link_libraries(securefs PRIVATE securefs-main)

if(0)
    add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28
                    -DUTF8PROC_EXPORTS=1)
    if(MSVC)
        add_executable(securefs main.cpp securefs.manifest)
    else()
        add_executable(securefs main.cpp)
    endif()
    if(UNIX)
        find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include/fuse
                                                /usr/local/include)
        if(SECUREFS_USE_FUSET)
            find_library(FUSE_LIBRARIES fuse-t PATHS /usr/local/lib)
        else()
            find_library(FUSE_LIBRARIES fuse PATHS /usr/local/lib)
        endif()

        target_include_directories(securefs-static SYSTEM AFTER
                                   PUBLIC ${FUSE_INCLUDE_DIR})
        target_link_libraries(securefs-static PUBLIC ${FUSE_LIBRARIES})
    else()
        target_compile_options(
            securefs-static PUBLIC -DNOMINMAX=1 -D_CRT_SECURE_NO_WARNINGS=1
                                   -D__STDC__=1 -DSTRSAFE_NO_DEPRECATE=1)
        if(NOT WINFSP_PREFIX)
            message("WINFSP_PREFIX not set, fallback to default value")
            set(WINFSP_PREFIX "C:/Program Files (x86)/WinFsp")
        endif()
        if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
            set(ARCH x64)
        else()
            set(ARCH x86)
        endif()
        set(FUSE_INCLUDE_DIR ${WINFSP_PREFIX}/inc/fuse)
        target_include_directories(
            securefs-static SYSTEM AFTER PUBLIC ${WINFSP_PREFIX}/inc
                                                ${FUSE_INCLUDE_DIR})
        target_link_libraries(securefs-static
                              PUBLIC ${WINFSP_PREFIX}/lib/winfsp-${ARCH}.lib)
        target_link_libraries(securefs-static PUBLIC delayimp.lib)
        if(MSVC)
            target_link_libraries(securefs-static
                                  PUBLIC -DELAYLOAD:winfsp-${ARCH}.dll)
            target_compile_options(securefs-static PUBLIC /utf-8)
        elseif(MINGW)
            target_link_libraries(securefs-static
                                  PUBLIC -delayload=winfsp-${ARCH}.dll)
        endif()
    endif()
    install(TARGETS securefs DESTINATION bin)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_FOUND AND SECUREFS_ENABLE_INTEGRATION_TEST)
        add_test(
            NAME simple_test
            COMMAND
                ${CMAKE_COMMAND} -E env SECUREFS_BINARY=$<TARGET_FILE:securefs>
                ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/simple_test.py)
    endif()
endif()
