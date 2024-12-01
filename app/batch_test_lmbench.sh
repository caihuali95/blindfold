#!/bin/sh

# Check if the script is running as root
if [ "$(whoami)" = "root" ]; then
  echo "This script must not be run as root."
  exit 1
else
  echo "Running as user."
fi

if [ -z "$1" ]; then
    echo "Usage: $0 nat|non|sen [N R]"
    exit 1
fi

N=10
R=10
if [ -n "$2" ]; then
    N=$2
fi
if [ -n "$3" ]; then
    R=$3
fi
echo "N=$N R=$R"

if [ "$1" = "nat" ]; then
    $HOME/test_lmbench.py nat -N $N -R $R
elif [ "$1" = "non" ]; then
    $HOME/adapted_otp
    if [ $? -ne 0 ]; then
        echo "Guardian is not running"
        exit 1
    fi
    $HOME/test_lmbench.py non -N $N -R $R
elif [ "$1" = "sen" ]; then
    $HOME/adapted_otp
    if [ $? -ne 0 ]; then
        echo "Guardian is not running"
        exit 1
    fi
    $HOME/test_lmbench.py sen -N $N -R $R
else
    echo "Usage: $0 nat|non|sen [N R]"
    exit 1
fi