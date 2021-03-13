#!/bin/sh
echo "Building 'rsatool_ui'..."
gcc rsatool_ui.c -o rsatool_ui -lrsatool -O0 -g2
echo "Done!"
