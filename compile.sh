#!/bin/bash

set -eux

OPENSSL_DIR="${HOME}/.local/openssl-4.1.0-dev-debug-26d762a108"

rm -f reproducer
gcc -o reproducer reproducer.c \
  -I"${OPENSSL_DIR}/include" \
  -L"${OPENSSL_DIR}/lib" \
  -lssl -lcrypto \
  -Wl,-rpath,"${OPENSSL_DIR}/lib"
