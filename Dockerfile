# syntax=docker/dockerfile:1

# Cross-compile on the build host (no QEMU) into a static musl binary.
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-bookworm AS builder

ARG TARGETARCH

# rust-lld ships with the toolchain and links the self-contained musl targets,
# so no system cross-linker is needed.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,id=spf-check-target-$TARGETARCH \
    case "$TARGETARCH" in \
        amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$RUST_TARGET" \
    && cargo build --release --locked --target "$RUST_TARGET" \
    && cp "target/$RUST_TARGET/release/spf-check" /spf-check

FROM scratch

COPY --from=builder /spf-check /spf-check

USER 1337
ENTRYPOINT ["/spf-check"]
