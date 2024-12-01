#!/bin/sh

if [ -z "$BF" ]; then
    echo "Please run this script with BF=<path to the Blindfold folder>"
    exit 1
fi

SRC=$BF/guardian
LINUX=$BF/build/rpi/build_linux
OUT=$BF/build/rpi/build_guardian
mkdir -p $OUT

echo "\e[0;32mbuilding guardian\e[0m"
RUSTSRC=$SRC OUT=$OUT LINUX=$LINUX make -C $SRC/lkm
echo "\e[0;32mdone building guardian\e[0m"
