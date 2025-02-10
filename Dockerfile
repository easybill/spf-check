FROM --platform=$BUILDPLATFORM rust:1.84.1-slim-bookworm AS builder

# Install build dependencies including cross-compilation tools
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    musl-tools \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy the entire project
COPY . .

# Build for release with static linking and specific target
RUN case "$TARGETPLATFORM" in \
        "linux/amd64")  \
            RUST_TARGET="x86_64-unknown-linux-musl" \
            ;; \
        "linux/arm64")  \
            RUST_TARGET="aarch64-unknown-linux-musl" \
            export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
            ;; \
        *)             \
            RUST_TARGET="x86_64-unknown-linux-musl" \
            ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build --release --target "$RUST_TARGET"

# Runtime stage
FROM scratch

# Copy the build artifact from the build stage
COPY --from=builder /usr/src/app/target/*/release/spf-check /spf-check

EXPOSE 8080

USER 1337

# Set the startup command to run our binary
CMD ["/spf-check"]
