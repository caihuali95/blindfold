#!/bin/sh

BUILD_SCRIPT=$HOME/lmbench/scripts/build

LINE="LDLIBS=\"\${LDLIBS} -ltirpc\""
if ! grep -Fxq "$LINE" "$BUILD_SCRIPT"; then
    # Use sed to insert the line before the last line
    sudo sed -i '$i'"$LINE" "$BUILD_SCRIPT"
fi

LINE="CFLAGS=\"\${CFLAGS} -I/usr/include/tirpc -I/usr/include/aarch64-linux-gnu\""
if ! grep -Fxq "$LINE" "$BUILD_SCRIPT"; then
    # Use sed to insert the line before the last line
    sudo sed -i '$i'"$LINE" "$BUILD_SCRIPT"
fi

echo "Building lmbench..."
sudo make -C $HOME/lmbench build
sudo mv $HOME/lmbench/bin $HOME/lmbench_bin
echo "Done"