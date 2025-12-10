# Dockerfile for building post-quantum BGPsec chain
# Author: Sam Moes
# Date: December 2024

FROM ubuntu:24.04

RUN apt update && apt install -y \
    git cmake ninja-build libssl-dev clang ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs first (dependency)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local . \
    && ninja install \
    && rm -rf /tmp/liboqs

# Copy local repo code into container (no git clone needed)
WORKDIR /code
COPY . .
RUN git remote add upstream https://github.com/open-quantum-safe/oqs-provider.git 2>/dev/null || true \
    && git fetch --all \
    && git reset --hard upstream/main \
    && git submodule update --init --recursive

# Build (clean any existing build artifacts first)
RUN rm -rf build _build && mkdir -p build && cd build \
    && cmake -GNinja .. -DCMAKE_BUILD_TYPE=Release \
    && ninja

ENV OPENSSL_MODULES=/code/build/lib
ENV OPENSSL_CONF=/code/bgpsec-openssl.cnf

WORKDIR /code/build
CMD ["bash"]