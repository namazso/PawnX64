# Copyright (C) 2022  namazso <admin@namazso.eu>
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
cmake_minimum_required(VERSION 3.14)
project(amx64)

add_library(${PROJECT_NAME} SHARED
        src/amx.cpp
        src/amx_windows.cpp
        src/amx_posix.cpp
        src/amx_compile.cpp
        src/amx_loader.cpp
        src/ensure_c_compatibility.c
        )

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /EHsc)
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -flto)
endif ()

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(${PROJECT_NAME} PRIVATE asmjit)

set(PUBLIC_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${PUBLIC_INCLUDE_DIR})
file(GLOB_RECURSE PUBLIC_INCLUDE_FILES "${PUBLIC_INCLUDE_DIR}/*")
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_INCLUDE_FILES}")
install(TARGETS ${PROJECT_NAME} ARCHIVE LIBRARY RUNTIME PUBLIC_HEADER)
