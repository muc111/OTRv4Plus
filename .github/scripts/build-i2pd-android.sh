#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Build the I2P router the APK carries (i2pd, with its SAM bridge) from
# source, for one Android ABI.
#
#   build-i2pd-android.sh <arm64-v8a|x86_64> <out-dir>
#
# Writes <out-dir>/jniLibs/<abi>/libi2pd.so (the i2pd EXECUTABLE: Android only
# extracts and allows exec of files in the APK's lib/<abi>/ named lib*.so)
# and <out-dir>/assets/i2pd-certificates.zip (reseed and family certificates, which
# i2pd needs to check what it downloads when it first joins the network).
#
# Every source is fetched by tag and then checked against the commit hash
# pinned below, so a moved tag fails the build instead of changing what
# ships. OpenSSL and Boost are linked statically; the only shared libraries
# the router needs are Android's own (libc, libm, libdl, libz).
#
# Needs ANDROID_NDK_LATEST_HOME (the GitHub runner has it) or ANDROID_NDK_HOME.
set -euo pipefail

ABI="${1:?usage: build-i2pd-android.sh <abi> <out-dir>}"
OUT="$(mkdir -p "${2:?usage: build-i2pd-android.sh <abi> <out-dir>}" && cd "$2" && pwd)"
API=26

# What ships. Changing a version means changing its hash in the same edit.
I2PD_TAG=2.59.0
I2PD_COMMIT=896f548175aa605efd15ecbfb744588e0c14f64f
OPENSSL_TAG=openssl-3.5.9
OPENSSL_COMMIT=45e844fa2a14ec92d146bd8f5778ac130b6625fb
BOOST_TAG=boost-1.88.0
BOOST_COMMIT=199ef13d6034c85232431130142159af3adfce22

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:?no Android NDK}}"
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
case "$ABI" in
  arm64-v8a) TRIPLE=aarch64-linux-android; OSSL_TARGET=android-arm64 ;;
  x86_64)    TRIPLE=x86_64-linux-android;  OSSL_TARGET=android-x86_64 ;;
  *) echo "unsupported ABI: $ABI" >&2; exit 2 ;;
esac
JOBS="$(nproc)"
WORK="${I2PD_WORK:-$PWD/i2pd-build}"
SRC="$WORK/src"
PREFIX="$WORK/prefix-$ABI"
mkdir -p "$SRC" "$PREFIX"

fetch() {  # fetch <url> <tag> <commit> <dir> [extra clone args]
  local url=$1 tag=$2 commit=$3 dir=$4; shift 4
  if [ ! -d "$SRC/$dir/.git" ]; then
    git clone -q --depth 1 --branch "$tag" "$@" "$url" "$SRC/$dir"
  fi
  local got
  got="$(git -C "$SRC/$dir" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    echo "::error::$dir: tag $tag is $got, pinned $commit" >&2
    exit 1
  fi
  echo "$dir $tag $got"
}

fetch https://github.com/PurpleI2P/i2pd "$I2PD_TAG" "$I2PD_COMMIT" i2pd
fetch https://github.com/openssl/openssl "$OPENSSL_TAG" "$OPENSSL_COMMIT" openssl
fetch https://github.com/boostorg/boost "$BOOST_TAG" "$BOOST_COMMIT" boost \
      --recurse-submodules --shallow-submodules -j "$JOBS"

# ── OpenSSL (static) ──────────────────────────────────────────────────────
if [ ! -f "$PREFIX/openssl/lib/libcrypto.a" ]; then
  rm -rf "$WORK/openssl-$ABI"
  cp -a "$SRC/openssl" "$WORK/openssl-$ABI"
  (
    cd "$WORK/openssl-$ABI"
    export ANDROID_NDK_ROOT="$NDK" PATH="$BIN:$PATH"
    ./Configure "$OSSL_TARGET" -D__ANDROID_API__=$API \
        no-shared no-tests no-docs no-apps no-module no-engine no-legacy \
        --prefix="$PREFIX/openssl" --libdir=lib
    make -j"$JOBS" build_libs >/dev/null
    make install_dev >/dev/null
  )
fi

# ── Boost: filesystem and program_options (static), plus headers ──────────
if [ ! -f "$PREFIX/boost/lib/libboost_program_options.a" ]; then
  (
    cd "$SRC/boost"
    [ -x ./b2 ] || ./bootstrap.sh >/dev/null
    cat > "$WORK/user-config-$ABI.jam" <<EOF
using clang : android
  : $BIN/${TRIPLE}${API}-clang++
  : <archiver>$BIN/llvm-ar <ranlib>$BIN/llvm-ranlib
  ;
EOF
    ./b2 -j"$JOBS" -q -d0 --user-config="$WORK/user-config-$ABI.jam" \
        --build-dir="$WORK/boost-build-$ABI" --prefix="$PREFIX/boost" \
        toolset=clang-android target-os=android \
        link=static runtime-link=shared threading=multi variant=release \
        cxxflags="-fPIC -std=c++20" \
        --with-filesystem --with-program_options --with-atomic \
        install
  )
fi

# ── i2pd ──────────────────────────────────────────────────────────────────
BUILD="$WORK/i2pd-build-$ABI"
rm -rf "$BUILD"
cmake -S "$SRC/i2pd/build" -B "$BUILD" -G "Unix Makefiles" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" -DANDROID_PLATFORM="android-$API" \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_FIND_ROOT_PATH="$PREFIX/boost;$PREFIX/openssl" \
    -DBoost_ROOT="$PREFIX/boost" -DBoost_USE_STATIC_LIBS=ON \
    -DOPENSSL_ROOT_DIR="$PREFIX/openssl" -DOPENSSL_USE_STATIC_LIBS=ON \
    -DCMAKE_CXX_FLAGS="-DANDROID_BINARY" \
    -DWITH_UPNP=OFF -DWITH_STATIC=OFF -DWITH_HARDENING=ON \
    -DWITH_LIBRARY=ON -DWITH_BINARY=ON -DBUILD_TESTING=OFF
cmake --build "$BUILD" -j"$JOBS" --target i2pd

mkdir -p "$OUT/jniLibs/$ABI" "$OUT/assets"
"$BIN/llvm-strip" -o "$OUT/jniLibs/$ABI/libi2pd.so" "$BUILD/i2pd"

# What it needs at run time: Android's own libraries only.
NEEDED="$("$BIN/llvm-readelf" -d "$OUT/jniLibs/$ABI/libi2pd.so" | awk '/NEEDED/{print $NF}' | tr -d '[]')"
echo "libi2pd.so ($ABI) needs: $(echo $NEEDED)"
for lib in $NEEDED; do
  case "$lib" in
    libc.so|libm.so|libdl.so|libz.so|liblog.so) ;;
    *) echo "::error::libi2pd.so ($ABI) needs $lib, which Android does not provide" >&2; exit 1 ;;
  esac
done

# Reseed and family certificates, the same for every ABI.
( cd "$SRC/i2pd/contrib" && rm -f "$OUT/assets/i2pd-certificates.zip" \
    && zip -q -r -X "$OUT/assets/i2pd-certificates.zip" certificates )

{
  echo "i2pd $I2PD_TAG $I2PD_COMMIT"
  echo "openssl $OPENSSL_TAG $OPENSSL_COMMIT"
  echo "boost $BOOST_TAG $BOOST_COMMIT"
} > "$OUT/i2pd-sources.txt"
ls -l "$OUT/jniLibs/$ABI" "$OUT/assets/i2pd-certificates.zip"
