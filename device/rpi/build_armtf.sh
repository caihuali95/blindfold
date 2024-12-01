#!/bin/sh

if [ -z "$BF" ]; then
    echo "Please run this script with BF=<path to the Blindfold folder>"
    exit 1
fi

DEBUG=1
LOG_LEVEL=50
SRC=$BF/arm-trusted-firmware

echo "\e[0;32mbuilding armtf\e[0m"
make -j12 -C $SRC PLAT=rpi4 CROSS_COMPILE=aarch64-linux-gnu- DEBUG=$DEBUG LOG_LEVEL=$LOG_LEVEL
echo "\e[0;32mdone building armtf\e[0m"