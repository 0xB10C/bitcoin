#!/usr/bin/env bash
#
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_usdt
export DOCKER_NAME_TAG=ubuntu:jammy
export PACKAGES="python3-zmq clang llvm libc++abi-dev libc++-dev bpfcc-tools"
export DEP_OPTS="NO_WALLET=1 CC=clang CXX='clang++ -stdlib=libc++'"
export GOAL="install"
export BITCOIN_CONFIG="--enable-reduce-exports CC=clang CXX='clang++ -stdlib=libc++'"

export RUN_FUNCTIONAL_TESTS="false"
export RUN_UNIT_TESTS="false"

export RUN_FUNCTIONAL_USDT_TESTS="true"
