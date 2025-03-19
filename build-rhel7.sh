#!/bin/sh
set -eux
yum install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum install -y -q gcc-c++ make cmake3 git
mkdir /build
cd /build
cmake3 -DCMAKE_BUILD_TYPE=RelWithDebInfo /src
cmake3 --build .
ctest3
cmake3 --install . --prefix /install
