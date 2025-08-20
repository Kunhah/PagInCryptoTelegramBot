# Stage 1: Build
FROM rust:1.88 as builder

# Set working directory to /app
WORKDIR /app

# Install system dependencies (PostgreSQL client lib for sqlx)
RUN apt-get update && apt-get install -y libpq-dev pkg-config

# Copy Cargo.toml and Cargo.lock to /app
COPY Cargo.toml Cargo.lock ./

# Copy src directory to /app/src
COPY src ./src

COPY .sqlx ./.sqlx 

# Build the application
RUN cargo build --release -v

# Stage 2: Runtime
FROM debian:bullseye-slim

# Set working directory to /app
WORKDIR /app

# Copy built binary and .sqlx metadata
COPY --from=builder /app/target/release/PagInCryptoBot /app/
COPY --from=builder /app/.sqlx /app/.sqlx

EXPOSE 8080

# Set command to run the application
CMD ["./PagInCryptoBot", "-v"]