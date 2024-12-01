#!/bin/sh

# Check if the script is running as root
if [ "$(whoami)" != "root" ]; then
  echo "This script must be run as root."
  exit 1
else
  echo "Running as root."
fi

BF=$(pwd)/../..
OUT=$BF/build/rpi
LINUX=$OUT/build_linux
GUARD=$BF/guardian/lkm
ARMTF=$BF/arm-trusted-firmware/build/rpi4/debug/
APPOUT=$OUT/build_app
APPSRC=$BF/app

SD1=$(lsblk | grep -o '\bsd.1\b')
SD2=$(lsblk | grep -o '\bsd.2\b')

MNT=$OUT/mnt
BOOT=$MNT/boot
ROOT=$MNT/root
mkdir -p $BOOT
mkdir -p $ROOT
mount --rw /dev/$SD1 $BOOT
mount --rw /dev/$SD2 $ROOT
DEVHOME=$ROOT/home/usr/

# Check the status of the mount command
if [ $? -eq 0 ]; then
    echo "Mount succeeded."
else
    echo "Mount failed with status $?"
    exit 1
fi

echo "\e[0;32minstalling armtf\e[0m"
rm -f $BOOT/bl31.bin
echo "copying $ARMTF/bl31.bin"
cp $ARMTF/bl31.bin $BOOT/bl31.bin
echo "\e[0;32mdone installing armtf\e[0m"

echo "\e[0;32minstalling linux\e[0m"
KERNEL=kernel8
env PATH=$PATH make -j8 -C $BF/linux O=$LINUX ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_PATH=$ROOT modules_install
cp $BOOT/$KERNEL.img $BOOT/$KERNEL-backup.img
cp $LINUX/arch/arm64/boot/Image $BOOT/$KERNEL.img
cp $LINUX/arch/arm64/boot/dts/broadcom/*.dtb $BOOT/
cp $LINUX/arch/arm64/boot/dts/overlays/*.dtb* $BOOT/overlays/
echo "\e[0;32mdone installing linux\e[0m"

echo "\e[0;32minstalling app\e[0m"
cp $APPSRC/run_me.sh $DEVHOME
cp $APPSRC/set_cpu_freq.sh $DEVHOME
cp -r $APPSRC/data $DEVHOME
cp -r $APPSRC/lmbench $DEVHOME
cp $APPSRC/build_lmbench.sh $DEVHOME
cp $APPSRC/test_lmbench.py $DEVHOME
cp $APPSRC/batch_test_lmbench.sh $DEVHOME
cp $APPSRC/print_lmbench_result.py $DEVHOME
cp -r $APPSRC/ltp $DEVHOME
cp $APPSRC/test_syscalls.py $DEVHOME
cp $APPSRC/test_app.py $DEVHOME
cp $APPOUT/adapter $DEVHOME
cp $APPOUT/nano $DEVHOME
cp $APPOUT/test $DEVHOME
cp $APPOUT/otp $DEVHOME
chmod 775 $DEVHOME*.sh
chmod 775 $DEVHOME*.py
echo "\e[0;32mdone installing app\e[0m"

echo "\e[0;32minstalling guardian\e[0m"
grep -qxF 'enable_uart=1' $BOOT/config.txt || sudo sed -i '$ s/$/enable_uart=1\n/' $BOOT/config.txt
grep -qxF 'enable_gic=1' $BOOT/config.txt || sudo sed -i '$ s/$/enable_gic=1\n/' $BOOT/config.txt
grep -qxF 'armstub=bl31.bin' $BOOT/config.txt || sudo sed -i '$ s/$/armstub=bl31.bin\n/' $BOOT/config.txt
grep -qxF 'dtoverlay=disable-bt' $BOOT/config.txt || sudo sed -i '$ s/$/dtoverlay=disable-bt\n/' $BOOT/config.txt
grep -qwF 'kpti=0' $BOOT/cmdline.txt || sudo sed -i '1s/^/kpti=0 /' $BOOT/cmdline.txt
grep -qxF 'kernel.randomize_va_space = 0' $ROOT/etc/sysctl.conf || sudo sed -i '$ s/$/kernel.randomize_va_space = 0\n/' $ROOT/etc/sysctl.conf
rm -f $ROOT/root/Guardian.ko
cp $GUARD/Guardian.ko $ROOT/root/
if [ $? -ne 0 ]; then
  echo "Copy Guardian.ko failed."
  exit 1
fi
sync
if [ ! -f "$ROOT/root/Guardian.ko" ]; then
    echo "Guardian.ko file does not exist"
    exit 1
fi
SOURCE_SIZE=$(stat -c%s "$GUARD/Guardian.ko")
DESTINATION_SIZE=$(stat -c%s "$ROOT/root/Guardian.ko")
if [ "$SOURCE_SIZE" -ne "$DESTINATION_SIZE" ]; then
    echo "Copy failed: file sizes do not match"
    exit 1
fi

umount $BOOT
umount $ROOT
echo "\e[0;32mdone installing\e[0m"
