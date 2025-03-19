#!/bin/sh
set -eux
dnf install -y -q gcc-c++ make cmake git
mkdir /build
cd /build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo /src
cmake --build .
ctest
cmake --install . --prefix /install
