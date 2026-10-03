#!/usr/bin/env bash
#
# Build the self-contained HTTP/3 native bundle for ioxide.nghttp3: nghttp3 (sans-I/O H3 + QPACK,
# ngtcp2's companion library) statically linked behind a small C shim into ONE shared library
# with no external dependencies beyond libc. nghttp3 does no I/O and no crypto - the transport
# is whatever QuicConnection the bridge rides on.
#
#   scripts/build-nghttp3-native.sh                 # build with the pinned ref below
#   NGHTTP3_REF=v1.18.0 scripts/build-nghttp3-native.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# PINNED, like build-ngtcp2-native.sh and for the same reasons: "master" meant two builds from one
# repo state could differ. This is the commit the shipped .so was built from (nghttp3 1.18.90; a
# build of it reproduces the shipped nghttp3 symbols exactly).
NGHTTP3_REF=${NGHTTP3_REF:-b1d0596fee2efb1f265fb921e46ef8525267aefe}
WORK=${WORK:-/tmp/ioxide-h3-native}
OUT=src/protocols/ioxide.nghttp3/runtimes/linux-x64/native

rm -rf "$WORK" && mkdir -p "$WORK" "$OUT"
cd "$WORK"

# Fetch the exact ref: --branch takes tags and branches, not commits.
echo "==> fetching nghttp3 ($NGHTTP3_REF)"
mkdir -p nghttp3
git -C nghttp3 init -q
git -C nghttp3 remote add origin https://github.com/ngtcp2/nghttp3
git -C nghttp3 fetch -q --depth 1 origin "$NGHTTP3_REF" || {
    echo "could not fetch $NGHTTP3_REF" >&2
    exit 1
}
git -C nghttp3 checkout -q FETCH_HEAD
git -C nghttp3 submodule update -q --init --depth 1 --recursive

echo "==> building nghttp3 (static, PIC)"
cmake -S nghttp3 -B nghttp3/build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DENABLE_LIB_ONLY=ON \
    -DENABLE_SHARED_LIB=OFF -DENABLE_STATIC_LIB=ON >/dev/null
cmake --build nghttp3/build -j"$(nproc)" >/dev/null

echo "==> compiling the C# facade shim"
SHIM="$OLDPWD/src/protocols/ioxide.nghttp3/native/ioxide_nghttp3_shim.c"
gcc -c -O2 -fPIC -o shim.o "$SHIM" \
    -Inghttp3/lib/includes -Inghttp3/build/lib/includes

echo "==> linking libioxide_nghttp3.so"
gcc -shared -o libioxide_nghttp3.so shim.o \
    -Wl,--whole-archive nghttp3/build/lib/libnghttp3.a -Wl,--no-whole-archive \
    -Wl,--no-undefined

echo "==> verifying"
ldd libioxide_nghttp3.so | grep -vE 'vdso|libc\.|ld-linux' && {
    echo "unexpected dependency"; exit 1; } || true
[ "$(nm -D --defined-only libioxide_nghttp3.so | grep -c ' ih3_')" -ge 8 ] || {
    echo "shim exports missing"; exit 1; }

cd - >/dev/null
cp "$WORK/libioxide_nghttp3.so" "$OUT/libioxide_nghttp3.so"
echo "==> done: $OUT/libioxide_nghttp3.so ($(du -h "$OUT/libioxide_nghttp3.so" | cut -f1))"
