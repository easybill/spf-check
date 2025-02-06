FROM rust:1.84.1-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install musl-tools for static linking
RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

# Set the target to musl for static linking with ARM64
RUN rustup target add aarch64-unknown-linux-musl

# Copy the Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo 'fn main() { println!("Dummy") }' > src/main.rs && \
    cargo build --release --target aarch64-unknown-linux-musl && \
    rm src/main.rs

# Now copy the actual source code
COPY src ./src

# Build for release with static linking
RUN touch src/main.rs && \
    cargo build --release --target aarch64-unknown-linux-musl

# Runtime stage
FROM scratch

# Copy the build artifact from the build stage
COPY --from=builder /usr/src/app/target/aarch64-unknown-linux-musl/release/spf-check /spf-check

EXPOSE 8080

# Set the startup command to run our binary
CMD ["/spf-check"]
