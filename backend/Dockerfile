FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY backend/Cargo.toml backend/Cargo.lock* ./backend/
COPY backend/src ./backend/src
COPY backend/public ./backend/public
COPY backend/project ./backend/project
RUN cargo build --release --manifest-path backend/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/backend/target/release/aegiscore /usr/local/bin/aegiscore
ENV PORT=3000 APP_ENV=preview COOKIE_SECURE=true
EXPOSE 3000
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aegiscore"]
