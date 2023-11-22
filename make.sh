#!/usr/bin/env bash

sudo apt install meson
sudo apt install libglib2.0-dev
sudo apt install pkg-config
sudo apt install libpixman-1-0

rm -rf build/
mkdir build/

./configure --target-list=x86_64-softmmu --disable-linux-io-uring
make -j `nproc`