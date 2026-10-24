#!/usr/bin/env bash
#
# Build the self-contained QUIC native bundle for ioxide.ngtcp2:
#   ngtcp2 (QUIC engine) + its picotls crypto backend + picotls (TLS 1.3 handshake) +
#   BoringSSL's libcrypto (the primitives picotls's OpenSSL backend calls),
# statically linked into ONE shared library whose only external dependency is libc. BoringSSL's
# symbols stay hidden inside it. Output lands in the package's runtimes/ dir so the nupkg carries
# everything.
#
#   scripts/build-ngtcp2-native.sh                 # build with pinned refs below
#   NGTCP2_REF=v1.14.0 scripts/build-ngtcp2-native.sh
#   RID=linux-arm64 scripts/build-ngtcp2-native.sh  # 64-bit ARM (see native-target.sh)
#
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/native-target.sh

# PINNED, and they have to stay pinned. These are security-critical dependencies compiled into a
# binary that ships in a nupkg, and the header ngtcp2's error constants are hand-copied from lives
# in this tree - so "master" meant the bundle could not be reproduced, two builds from one repo
# state could differ, and a constant could silently start meaning something else. It did: CLOSING
# and INTERNAL were both wrong, and were caught by a test that asks the library rather than by the
# build. These are the commits the shipped .so was built from.
NGTCP2_REF=${NGTCP2_REF:-7f7e24b1deb1dc94985c2d6345ca68cc387b4709}
PICOTLS_REF=${PICOTLS_REF:-f07f1c8c68b237f1468bc1f1fe1b68aba3ff23b4}
# The commit scripts/build-boringssl-native.sh pins; kept the same so ioxide ships one BoringSSL.
BORINGSSL_REF=${BORINGSSL_REF:-5b83e5d1abf0ae0033ae52ab579d906b67633b2c}
WORK=${WORK:-/tmp/ioxide-quic-native}
OUT=src/protocols/ioxide.ngtcp2/runtimes/$RID/native

rm -rf "$WORK" && mkdir -p "$WORK" "$OUT"
cd "$WORK"

echo "==> fetching boringssl ($BORINGSSL_REF) + picotls ($PICOTLS_REF) + ngtcp2 ($NGTCP2_REF)"

# Fetch the exact ref rather than cloning a branch: --branch takes tags and branches, and these are
# commits. Falling back to a plain clone - as this used to - would quietly build something else.
fetch_at() {   # url, ref, dir
    mkdir -p "$3"
    git -C "$3" init -q
    git -C "$3" remote add origin "$1" 2>/dev/null || true
    git -C "$3" fetch -q --depth 1 origin "$2" || {
        echo "could not fetch $2 from $1" >&2
        exit 1
    }
    git -C "$3" checkout -q FETCH_HEAD
    git -C "$3" submodule update -q --init --depth 1 --recursive
}

fetch_at https://github.com/google/boringssl "$BORINGSSL_REF" boringssl
fetch_at https://github.com/h2o/picotls "$PICOTLS_REF" picotls
fetch_at https://github.com/ngtcp2/ngtcp2 "$NGTCP2_REF" ngtcp2

echo "==> building boringssl (static, PIC, symbols hidden)"
cmake -S boringssl -B boringssl/build -DCMAKE_BUILD_TYPE=Release "${CMAKE_TARGET[@]}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
cmake --build boringssl/build --target crypto ssl decrepit -j"$(nproc)" >/dev/null
# The layout picotls's FIND_PACKAGE(OpenSSL) expects; it recognises BoringSSL by openssl/base.h.
mkdir -p boringssl-root/lib
ln -s "$WORK/boringssl/include" boringssl-root/include
cp boringssl/build/libcrypto.a boringssl/build/libssl.a boringssl/build/libdecrepit.a boringssl-root/lib/

echo "==> building picotls (static, PIC, on BoringSSL)"
cmake -S picotls -B picotls/build -DCMAKE_BUILD_TYPE=Release "${CMAKE_TARGET[@]}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DWITH_FUSION=OFF \
    -DOPENSSL_ROOT_DIR="$WORK/boringssl-root" -DOPENSSL_USE_STATIC_LIBS=TRUE >/dev/null
# Only the two archives: the test programs would link libssl, which is C++.
cmake --build picotls/build --target picotls-core picotls-openssl -j"$(nproc)" >/dev/null

echo "==> building ngtcp2 + crypto_picotls (static, PIC, default visibility)"
# ngtcp2 pins hidden visibility on its static targets; the bundle needs the API exported.
sed -i 's/C_VISIBILITY_PRESET hidden/C_VISIBILITY_PRESET default/' \
    ngtcp2/lib/CMakeLists.txt ngtcp2/crypto/picotls/CMakeLists.txt
# ngtcp2 finds "OpenSSL" for the picotls backend too; pointed at BoringSSL, whose version lives in
# base.h where FindOpenSSL does not look, so the 1.1.1 floor would refuse it. -I BoringSSL first:
# picotls/openssl.h includes <openssl/...>, which would otherwise find the system's headers.
sed -i 's/find_package(OpenSSL 1.1.1 REQUIRED)/find_package(OpenSSL REQUIRED)/' ngtcp2/CMakeLists.txt
cmake -S ngtcp2 -B ngtcp2/build -DCMAKE_BUILD_TYPE=Release "${CMAKE_TARGET[@]}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF \
    -DCMAKE_C_FLAGS="-I$WORK/boringssl/include" \
    -DOPENSSL_ROOT_DIR="$WORK/boringssl-root" -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DENABLE_PICOTLS=ON -DENABLE_OPENSSL=OFF -DENABLE_GNUTLS=OFF \
    -DENABLE_SHARED_LIB=OFF -DENABLE_STATIC_LIB=ON \
    -DPICOTLS_INCLUDE_DIR="$WORK/picotls/include" \
    "-DPICOTLS_LIBRARIES=$WORK/picotls/build/libpicotls-openssl.a;$WORK/picotls/build/libpicotls-core.a;$WORK/boringssl-root/lib/libdecrepit.a;$WORK/boringssl-root/lib/libcrypto.a;stdc++" >/dev/null
cmake --build ngtcp2/build -j"$(nproc)" >/dev/null

echo "==> compiling the C# facade shim"
SHIM="$OLDPWD/src/protocols/ioxide.ngtcp2/native/ioxide_ngtcp2_shim.c"
"$CC" -c -O2 -fPIC -o shim.o "$SHIM" -I"$WORK/boringssl/include" \
    -Ingtcp2/lib/includes -Ingtcp2/build/lib/includes \
    -Ingtcp2/crypto/includes -Ipicotls/include

echo "==> linking libioxide_ngtcp2.so"
# std:: vtables and typeinfo that BoringSSL's own objects instantiate stay local too.
echo '{ local: _ZSt*; _ZNSt*; _ZNKSt*; _ZTISt*; _ZTSSt*; _ZTVSt*; };' >std-local.map
# picotls's Blowfish (CID encryption) is in BoringSSL's libdecrepit. BoringSSL is C++ built without
# exceptions or RTTI: the little it needs from the C++ runtime is linked in, and hidden.
"$CXX" -shared -o libioxide_ngtcp2.so shim.o \
    -Wl,--whole-archive \
    ngtcp2/build/lib/libngtcp2.a \
    ngtcp2/build/crypto/picotls/libngtcp2_crypto_picotls.a \
    picotls/build/libpicotls-openssl.a \
    picotls/build/libpicotls-core.a \
    -Wl,--no-whole-archive boringssl-root/lib/libdecrepit.a boringssl-root/lib/libcrypto.a \
    -static-libstdc++ -static-libgcc -lpthread -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,--exclude-libs,libstdc++.a:libgcc.a:libgcc_eh.a -Wl,--version-script=std-local.map
"$STRIP" --strip-unneeded libioxide_ngtcp2.so   # BoringSSL builds with -ggdb

echo "==> verifying"
"$READELF" -d libioxide_ngtcp2.so | grep NEEDED | grep -vE 'libc\.|ld-linux' && {
    echo "unexpected dependency"; exit 1; } || true
# BoringSSL is linked in, not offered: its symbols must not be exported for anything else to bind.
"$NM" -D --defined-only libioxide_ngtcp2.so | grep -qE ' ((EVP|X509|SSL|BIO)_|_Z)' && {
    echo "BoringSSL or C++ symbols exported"; exit 1; } || true
[ "$("$NM" -D --defined-only libioxide_ngtcp2.so | grep -c ' ngtcp2_')" -gt 500 ] || {
    echo "ngtcp2 exports missing"; exit 1; }
[ "$("$NM" -D --defined-only libioxide_ngtcp2.so | grep -c ' ptls_')" -gt 100 ] || {
    echo "picotls exports missing"; exit 1; }
[ "$("$NM" -D --defined-only libioxide_ngtcp2.so | grep -c ' iq_')" -ge 13 ] || {
    echo "shim exports missing"; exit 1; }

cd - >/dev/null
cp "$WORK/libioxide_ngtcp2.so" "$OUT/libioxide_ngtcp2.so"
echo "==> done: $OUT/libioxide_ngtcp2.so ($(du -h "$OUT/libioxide_ngtcp2.so" | cut -f1))"
