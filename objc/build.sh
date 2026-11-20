#!/bin/sh
# Build with GNUstep on Linux:  apt install gobjc gnustep-make libgnustep-base-dev libsqlite3-dev libssl-dev
set -e
cd "$(dirname "$0")"
gcc -w $(gnustep-config --objc-flags) main.m Common.m cases/*.m -o vulnobjc \
    $(gnustep-config --base-libs) -lsqlite3 -lcrypto
