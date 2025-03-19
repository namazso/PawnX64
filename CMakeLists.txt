# Copyright (C) 2022  namazso <admin@namazso.eu>
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
cmake_minimum_required(VERSION 3.14)
project(PawnX64)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 11)

set(ASMJIT_NO_INSTALL TRUE)
set(ASMJIT_STATIC TRUE)
set(ASMJIT_NO_CUSTOM_FLAGS TRUE)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if ("${CMAKE_EXECUTABLE_SUFFIX}" STREQUAL "")
    set(CMAKE_EXECUTABLE_SUFFIX ".bin")
endif ()

add_subdirectory(${CMAKE_SOURCE_DIR}/asmjit)

add_subdirectory(${CMAKE_SOURCE_DIR}/amx64)

add_subdirectory(${CMAKE_SOURCE_DIR}/pawnrun)

if (UNIX)
    add_subdirectory(${CMAKE_SOURCE_DIR}/signalmgr)
endif ()

option(AMX_NO_TESTS "Disable tests")

if (NOT AMX_NO_TESTS)
    include(CTest)
    add_subdirectory(${CMAKE_SOURCE_DIR}/amx64_test)
endif ()
