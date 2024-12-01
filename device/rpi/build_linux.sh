#!/bin/sh

if [ -z "$BF" ]; then
    echo "Please run this script with BF=<path to the Blindfold folder>"
    exit 1
fi

SRC=$BF/linux
OUT=$BF/build/rpi/build_linux
mkdir -p $OUT

echo "\e[0;32mbuilding linux\e[0m"
make -j12 -C $SRC O=$OUT ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- bcm2711_defconfig
sed -i 's/CONFIG_LOCALVERSION=\"-v8\"/CONFIG_LOCALVERSION=\"-Blindfold\"/' $OUT/.config
make -j12 -C $SRC O=$OUT ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image modules dtbs
echo "\e[0;32mdone building linux\e[0m"
