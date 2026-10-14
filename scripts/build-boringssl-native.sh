#!/usr/bin/env bash
#
# Build the TLS native bundle for ioxide: BoringSSL (libssl + libcrypto) statically linked into ONE
# shared library, libioxide_boringssl.so, whose only external dependency is libc. Both TLS columns
# use it - the userspace one for every record, the kTLS one for the handshake - and so does
# ioxide.httpclient. Output lands in the package's runtimes/ dir so the nupkg carries everything.
#
#   scripts/build-boringssl-native.sh                 # build with the pinned ref below
#   BORINGSSL_REF=<commit> scripts/build-boringssl-native.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# PINNED, like the other native scripts: a security-critical library compiled into a binary that
# ships in a nupkg has to be reproducible. BoringSSL has no releases; this is the main commit the
# shipped .so was built from (2026-10-11). It needs SSL_CTX_set1_tls13_ciphers, which is recent.
BORINGSSL_REF=${BORINGSSL_REF:-5b83e5d1abf0ae0033ae52ab579d906b67633b2c}
WORK=${WORK:-/tmp/ioxide-boringssl-native}
OUT=src/ioxide/runtimes/linux-x64/native

rm -rf "$WORK" && mkdir -p "$WORK" "$OUT"
cd "$WORK"

echo "==> fetching boringssl ($BORINGSSL_REF)"
mkdir -p boringssl
git -C boringssl init -q
git -C boringssl remote add origin https://github.com/google/boringssl
git -C boringssl fetch -q --depth 1 origin "$BORINGSSL_REF" || {
    echo "could not fetch $BORINGSSL_REF" >&2
    exit 1
}
git -C boringssl checkout -q FETCH_HEAD

echo "==> building libssl + libcrypto (static, PIC, public API exported)"
# BORINGSSL_SHARED_LIBRARY gives OPENSSL_EXPORT default visibility in the static archives; every
# internal symbol stays hidden.
cmake -S boringssl -B boringssl/build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_C_FLAGS=-DBORINGSSL_SHARED_LIBRARY -DCMAKE_CXX_FLAGS=-DBORINGSSL_SHARED_LIBRARY >/dev/null
cmake --build boringssl/build --target ssl crypto -j"$(nproc)" >/dev/null

echo "==> linking libioxide_boringssl.so"
# std:: vtables and typeinfo that BoringSSL's own objects instantiate stay local too.
echo '{ local: _ZSt*; _ZNSt*; _ZNKSt*; _ZTISt*; _ZTSSt*; _ZTVSt*; };' >std-local.map
# -Bsymbolic: .NET loads the system's OpenSSL into the same process for its own crypto, and the
# names are the same; every call inside this library has to stay inside it. BoringSSL is C++ built
# without exceptions or RTTI: the little it needs from the C++ runtime is linked in, and hidden.
g++ -shared -o libioxide_boringssl.so -Wl,-soname,libioxide_boringssl.so \
    -Wl,--whole-archive boringssl/build/libssl.a boringssl/build/libcrypto.a -Wl,--no-whole-archive \
    -Wl,-Bsymbolic -Wl,--no-undefined -static-libstdc++ -static-libgcc -lpthread \
    -Wl,--exclude-libs,libstdc++.a:libgcc.a:libgcc_eh.a -Wl,--version-script=std-local.map
strip --strip-unneeded libioxide_boringssl.so

echo "==> verifying"
ldd libioxide_boringssl.so | grep -vE 'vdso|libc\.|libm\.|ld-linux' && {
    echo "unexpected dependency"; exit 1; } || true
nm -D --defined-only libioxide_boringssl.so | awk '{print $3}' >exports.txt
for symbol in SSL_CTX_new SSL_CTX_set1_tls13_ciphers SSL_CTX_set_min_proto_version \
    SSL_CTX_set_tlsext_servername_callback SSL_CTX_set_keylog_callback SSL_get_ex_new_index \
    BIO_s_mem PEM_read_bio_PrivateKey X509_verify_cert_error_string; do
    grep -qx "$symbol" exports.txt || { echo "missing export $symbol"; exit 1; }
done
[ "$(grep -c '^SSL_' exports.txt)" -gt 300 ] || { echo "libssl exports missing"; exit 1; }
[ "$(grep -c '^EVP_' exports.txt)" -gt 200 ] || { echo "libcrypto exports missing"; exit 1; }
c++filt <exports.txt | grep -qE '^(std::|__gnu_cxx::|operator (new|delete)|__cxa)' && {
    echo "C++ runtime symbols exported"; exit 1; } || true

cd - >/dev/null
cp "$WORK/libioxide_boringssl.so" "$OUT/libioxide_boringssl.so"
echo "==> done: $OUT/libioxide_boringssl.so ($(du -h "$OUT/libioxide_boringssl.so" | cut -f1))"
