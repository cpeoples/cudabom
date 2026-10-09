# Local Linux test parity for macOS developers.
#
# cudabom's real-binary tests (crates/cudabom-elf/tests/real_so_linux.rs,
# crates/cudabom-identify/tests/*_linux.rs, ...) are gated to Linux because they
# compile real ELF shared objects and relocatable `.o`s with the system
# toolchain and assert cudabom recovers their facts (SONAME, build-id, dynamic
# and static symbol tables). On macOS the toolchain emits Mach-O, so those tests
# silently skip and the exact path Lever 2 depends on goes locally unverified.
#
# This image reproduces the CI Linux environment (the repo-pinned Rust toolchain
# plus a C toolchain) so you can run the identical gate locally. It is a
# developer convenience, NOT a packaging or distribution image and NOT a build
# dependency: CI already runs the same tests on its Linux matrix (see
# .github/workflows/ci.yml), using the same rust-toolchain.toml pin.
#
# Usage (from the repository root):
#
#   docker build -f .docker/linux-tests.Dockerfile -t cudabom-linux-tests .
#   docker run --rm cudabom-linux-tests
#
# Or iterate against your live working tree without rebuilding the image, by
# mounting the repo over the baked-in copy (cargo caches persist in the image):
#
#   docker run --rm -v "$PWD":/cudabom cudabom-linux-tests
#
# Pin to a digest-stable Debian-based Rust image. The exact Rust version used is
# governed by the repo's rust-toolchain.toml (copied in below), not by this base
# image's baked-in toolchain, so the container compiles with the identical
# compiler as local and CI. `cc`/`gcc` ship in this image already, which is
# exactly what the real-ELF tests probe for on PATH.
FROM rust:1-bookworm

# Explicit about the one runtime fact the tests need: a C compiler on PATH.
# `build-essential` provides `cc`, `gcc`, and `ar`; it is present in the base
# image but installed here so the dependency is documented and self-contained.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /cudabom

# Install the exact toolchain the repo pins *before* copying the full source, so
# the (slow) toolchain download is a cached layer and a pin bump is the only
# thing that invalidates it. rustup reads the channel/components from this file.
COPY rust-toolchain.toml ./
RUN rustup show active-toolchain || rustup toolchain install

# Bake the sources in so `docker run` works with no mount. A bind mount over
# /cudabom (see header) overrides this for live-tree iteration.
COPY . .

# Default: run the exact gate CI runs, so a green run here means a green run
# there. `--locked` matches CI and fails if Cargo.lock would change.
CMD ["sh", "-c", "cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked"]
