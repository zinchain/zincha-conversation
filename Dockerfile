FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin zincha-conversation \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/zincha-conversation /usr/local/bin/zincha-conversation
USER 10001:10001
EXPOSE 443 9988
ENTRYPOINT ["/usr/local/bin/zincha-conversation"]
