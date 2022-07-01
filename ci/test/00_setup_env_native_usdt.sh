#!/usr/bin/env bash
#
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# We install an up-to-date 'bpfcc-tools' package from an untrusted PPA.
# This can be dropped with the next Ubuntu or Debian release that includes up-to-date packages.
# See the if-then in ci/test/04_install.sh too.
export ADD_UNTRUSTED_BPFCC_PPA=true
export TRACING_PACKAGES="systemtap-sdt-dev bpfcc-tools"
export PACKAGES="clang llvm python3-zmq qtbase5-dev qttools5-dev-tools libevent-dev bsdmainutils libboost-dev libdb5.3++-dev libminiupnpc-dev libnatpmp-dev libzmq3-dev libqrencode-dev libsqlite3-dev $TRACING_PACKAGES"
export NO_DEPENDS=1
export GOAL="install"
export BITCOIN_CONFIG="--enable-c++20 --enable-zmq --enable-usdt --disable-bench --disable-fuzz --with-incompatible-bdb --without-gui CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER' CC=clang CXX=clang++"
