# Sourced by the build-*-native.sh scripts: the runtime identifier they build for, and its toolchain.
#
#   scripts/build-ngtcp2-native.sh                    # linux-x64, the default
#   RID=linux-arm64 scripts/build-ngtcp2-native.sh    # 64-bit ARM
#
# A target other than the host's own architecture is cross-compiled with the <arch>-linux-gnu-
# toolchain (Debian/Ubuntu: gcc-aarch64-linux-gnu g++-aarch64-linux-gnu, or the x86-64-linux-gnu pair).
RID=${RID:-linux-x64}
case "$RID" in
    linux-x64) ARCH=x86_64 ;;
    linux-arm64) ARCH=aarch64 ;;
    *) echo "unsupported RID '$RID': linux-x64 or linux-arm64" >&2; exit 1 ;;
esac

TOOL=
CMAKE_TARGET=()
if [ "$(uname -m)" != "$ARCH" ]; then
    TOOL=$ARCH-linux-gnu-
    command -v "${TOOL}g++" >/dev/null || { echo "building $RID here needs ${TOOL}gcc and ${TOOL}g++" >&2; exit 1; }
    CMAKE_TARGET=(-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$ARCH"
        -DCMAKE_C_COMPILER="${TOOL}gcc" -DCMAKE_CXX_COMPILER="${TOOL}g++")
fi
CC=${TOOL}gcc
CXX=${TOOL}g++
STRIP=${TOOL}strip
NM=${TOOL}nm
READELF=${TOOL}readelf
