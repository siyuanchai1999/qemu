#!/bin/bash
cp configs/targets/x86_64_ecpt-softmmu.mak configs/targets/x86_64-softmmu.mak
CFLAGS="-Wno-unused-function" ./configure --target-list=x86_64-softmmu --enable-plugins --enable-debug --disable-linux-io-uring
