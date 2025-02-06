FROM rust:1.84.1-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy the Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo 'fn main() { println!("Dummy") }' > src/main.rs && \
    cargo build --release && \
    rm src/main.rs

# Now copy the actual source code
COPY src ./src

# Build for release with static linking and specific target
RUN touch src/main.rs && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM scratch

# Copy the build artifact from the build stage
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/spf-check /spf-check

EXPOSE 8080

# Set the startup command to run our binary
CMD ["/spf-check"]
