#!/bin/bash
cp configs/targets/x86_64_radix-softmmu.mak configs/targets/x86_64-softmmu.mak
./configure --target-list=x86_64-softmmu --enable-debug --disable-linux-io-uring
