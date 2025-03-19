#!/bin/sh
set -eux
apk update -q
apk add -q g++ make cmake git
mkdir /build
cd /build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo /src
cmake --build .
ctest
cmake --install . --prefix /install
