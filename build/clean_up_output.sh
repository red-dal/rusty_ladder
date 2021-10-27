#!/bin/bash
# Remove everything in output and target directory.

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
rm -rf $TARGET_DIR
rm -rf $OUTPUT_DIR