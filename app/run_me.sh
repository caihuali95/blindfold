#!/bin/sh

# Check if the script is running as root
if [ "$(whoami)" = "root" ]; then
    echo "Starting Guardian in root mode."
    sudo insmod /root/Guardian.ko
    echo "done."
    exit 0
else
    echo "Running as user."
fi

sudo chown -R $(whoami) ./*
sudo ./set_cpu_freq.sh
sudo apt install automake -y

if [ ! -f "$HOME/adapter" ]; then
    echo "adapter does not exist and no way to retrofit the apps"
    exit 1
fi

echo "adapting otp"
$HOME/adapter otp
chmod +x $HOME/adapted_otp

echo "adapting test"
$HOME/adapter test
chmod +x $HOME/adapted_test

./build_lmbench.sh
python3 ./test_syscalls.py -p
python3 ./test_syscalls.py -b
