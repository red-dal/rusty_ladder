#!/bin/bash
# Build binaries using cargo cross for all target in TARGET_LIST 
# and put them into OUTPUT_DIR.
#
# The image used to build each target must be specified in Cross.toml.

set -ex

# Directory of build.sh and Dockerfiles.
BUILD_DIR=$(cd $(dirname $0) && pwd)
# Directory of the project, usually the parent of BUILD_DIR.
WORK_DIR=$(cd $BUILD_DIR/.. && pwd)
# Directory of build result.
TARGET_DIR=$WORK_DIR/target
# Directory of the rusty_ladder crate
RUSTY_LADDER_DIR=$WORK_DIR/rusty_ladder
VERSION=$(grep -E '^version' $RUSTY_LADDER_DIR/Cargo.toml | awk '{print $3}' | sed 's/"//g')

# All built binaries will be in here.
OUTPUT_DIR=$BUILD_DIR/output

TARGET_LIST=(
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-gnu
)

NO_OPENSSL_TARGET_LIST=(
    x86_64-pc-windows-gnu
)

FEATURES="parse-config parse-url-v2rayn use-tui all-transports-rustls all-proxies-ring use-udp"
WIN_FEATURES="parse-config parse-url-v2rayn use-tui all-transports-rustls all-proxies-ring use-udp"

# Make docker images
cd $BUILD_DIR
for target in "${TARGET_LIST[@]}"; do
    docker build -t build_ladder_$target -f Dockerfile.$target .
done
# Build with cross
cd $WORK_DIR
export RUSTFLAGS='-C link-arg=-s'
for target in "${TARGET_LIST[@]}"; do
    cross build --release --no-default-features --features "$FEATURES" --target $target
done
for target in "${NO_OPENSSL_TARGET_LIST[@]}"; do
    cross build --release --no-default-features --features "$WIN_FEATURES" --target $target
done
# Package
cd $TARGET_DIR

function package_target {
    local target=$1
    local zip_file="rusty_ladder-v$VERSION.$target.zip"

    local rusty_ladder_file=$target/release/rusty_ladder
    if [[ $target == "x86_64-pc-windows-gnu" ]]; then
        rusty_ladder_file=$target/release/rusty_ladder.exe
    fi

    zip -j $zip_file $rusty_ladder_file $WORK_DIR/COPYING $WORK_DIR/rusty_ladder/examples/example*
    sha512sum $zip_file > $zip_file.sha512
    mkdir -p $OUTPUT_DIR
    mv $zip_file* $OUTPUT_DIR/
}

for target in "${TARGET_LIST[@]}"; do
    package_target $target
done

for target in "${NO_OPENSSL_TARGET_LIST[@]}"; do
    package_target $target
done
