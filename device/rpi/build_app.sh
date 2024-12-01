#!/bin/sh

if [ -z "$BF" ]; then
    echo "Please run this script with BF=<path to the Blindfold folder>"
    exit 1
fi

SRC=$BF/app
OUT=$BF/build/rpi/build_app
mkdir -p $OUT

echo "\e[0;32mbuilding app\e[0m"
CXX=aarch64-linux-gnu-g++ OUT=$OUT make -C $SRC/adapter
CC=aarch64-linux-gnu-gcc  OUT=$OUT make -C $SRC/nano
CC=aarch64-linux-gnu-gcc  OUT=$OUT make -C $SRC/test
CC=aarch64-linux-gnu-gcc  OUT=$OUT make -C $SRC/otp
echo "\e[0;32mdone building app\e[0m"
