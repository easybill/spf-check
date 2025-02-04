FROM rust:1.84.1-slim-bookworm AS builder

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

# Build for release
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the build artifact from the build stage
COPY --from=builder /usr/src/app/target/release/spf-check /usr/local/bin/

EXPOSE 8080

# Set the startup command to run our binary
CMD ["spf-check"]