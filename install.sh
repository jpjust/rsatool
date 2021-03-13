#!/bin/sh
echo "Copying 'librsatool.so' to /usr/local/lib..."
cp -f ./Release/librsatool.so /usr/local/lib
echo "Copying 'rsatool.h' to /usr/local/include..."
cp -f ./rsatool.h /usr/local/include
echo "Updating shared library links..."
ldconfig
echo "Done!"
