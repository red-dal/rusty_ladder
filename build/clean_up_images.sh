#!/bin/bash
# Clean up all docker images.

set -ex

TARGET_LIST=(
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-gnu
)

for target in "${TARGET_LIST[@]}"; do
    docker rmi build_ladder_$target
done