#!/usr/bin/env bash
#
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export BCC_KERNEL_SOURCE="/lib/modules/5.15.0-1010-gcp/build"
export DOCKER_NAME_TAG="debian:bookworm"
export CONTAINER_NAME=ci_native_usdt
# We install an up-to-date 'bpfcc-tools' package from an untrusted PPA.
# This can be dropped with the next Ubuntu or Debian release that includes up-to-date packages.
# See the if-then in ci/test/04_install.sh too.
export TRACING_PACKAGES="bpfcc-tools"
export PACKAGES="libevent-dev bsdmainutils libboost-dev $TRACING_PACKAGES"
export RUN_UNIT_TESTS=false
#export RUN_FUNCTIONAL_TESTS=false
export DEP_OPTS="NO_QT=1 NO_UPNP=1 NO_NATPMP=1"
#export NO_DEPENDS=1
export GOAL="install"
export BITCOIN_CONFIG="--enable-usdt --disable-bench --disable-fuzz"
