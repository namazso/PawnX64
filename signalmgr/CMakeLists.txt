# Copyright (C) 2022  namazso <admin@namazso.eu>
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
cmake_minimum_required(VERSION 3.14)
project(signalmgr)

add_library(${PROJECT_NAME} SHARED
        src/signalmgr.cpp
        )

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(${PROJECT_NAME} PRIVATE dl)

set(PUBLIC_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${PUBLIC_INCLUDE_DIR})
file(GLOB_RECURSE PUBLIC_INCLUDE_FILES "${PUBLIC_INCLUDE_DIR}/*")
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_INCLUDE_FILES}")
install(TARGETS ${PROJECT_NAME} ARCHIVE LIBRARY RUNTIME PUBLIC_HEADER)
