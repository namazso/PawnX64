# Copyright (C) 2022  namazso <admin@namazso.eu>
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
cmake_minimum_required(VERSION 3.14)
project(amx64_test)

include(../cmake-bin2h/bin2h.cmake)

bin2h(SOURCE_FILE test.amx HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/include/test_amx.h" VARIABLE_NAME test_amx)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

# this is build time only, so we just vendor it.
include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG 489283524e3726b7adb9692763c2fb61b235d41a
)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE amx64 gtest gtest_main)

if (UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE signalmgr)
endif ()

target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include")

gtest_discover_tests(${PROJECT_NAME})
