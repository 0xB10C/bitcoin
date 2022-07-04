#!/usr/bin/env bash
#
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export DOCKER_NAME_TAG="debian:bookworm"
export CONTAINER_NAME=ci_native_usdt
# We install an up-to-date 'bpfcc-tools' package from an untrusted PPA.
# This can be dropped with the next Ubuntu or Debian release that includes up-to-date packages.
# See the if-then in ci/test/04_install.sh too.
export TRACING_PACKAGES="systemtap-sdt-dev bpfcc-tools"
export PACKAGES="clang llvm libevent-dev bsdmainutils libboost-dev $TRACING_PACKAGES"
export RUN_UNIT_TESTS=false
export NO_DEPENDS=1
export GOAL="install"
export BITCOIN_CONFIG="--enable-c++20 --enable-zmq --enable-usdt --disable-bench --disable-fuzz --with-incompatible-bdb --without-gui CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER' CC=clang CXX=clang++"
