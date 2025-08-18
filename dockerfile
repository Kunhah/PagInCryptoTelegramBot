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

# Build the application
RUN cargo build --release -v

# Stage 2: Runtime
FROM debian:bullseye-slim

# Set working directory to /app
WORKDIR /app

# Copy the built application from the builder stage
COPY --from=builder /app/target/release/PagInCryptoBot /app/

# Expose port 8080
EXPOSE 8080

# ENVIRONMENT VARIABLES
ENV TELOXIDE_TOKEN=${TELOXIDE_TOKEN}
ENV GROUP_ID=${GROUP_ID}
ENV DATABASE_URL=${DATABASE_URL}
ENV STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET}


# Set command to run the application
CMD ["./PagInCryptoBot"]