# Copyright (C) 2022  namazso <admin@namazso.eu>
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
cmake_minimum_required(VERSION 3.14)
project(pawnrun)

add_executable(${PROJECT_NAME} src/main.cpp)

install(TARGETS ${PROJECT_NAME} ARCHIVE LIBRARY RUNTIME PUBLIC_HEADER)

target_link_libraries(${PROJECT_NAME} PRIVATE amx64)

if (UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE signalmgr)
endif ()
