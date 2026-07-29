# Build against musl so the result is a single static binary, then ship it on
# nothing at all. TLS roots come from webpki-roots and are compiled in, so the
# runtime image needs no CA bundle — and with no shell, no package manager and
# no libc, there is nothing in the image to pivot to if the proxy is ever
# compromised.

FROM rust:alpine AS build
# ring compiles C, so the build stage needs a toolchain the runtime never sees.
RUN apk add --no-cache musl-dev
WORKDIR /src

# Dependencies first, in their own layer: source edits are frequent and
# dependency changes are rare, so this keeps rebuilds to the crate that changed.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Touch so cargo cannot mistake the real sources for the stub it just built.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# A directory to hand to the runtime stage. Docker seeds a fresh named volume
# from the image, ownership included, so this is what makes /data writable by an
# unprivileged uid in an image that has no shell to chown it later.
RUN mkdir -p /seed/data

FROM scratch
COPY --from=build /src/target/release/sluice /sluice
COPY --from=build --chown=10001:10001 /seed/data /data

# Unprivileged by construction: no passwd file exists, so the numeric id is the
# identity. Nothing in the image is writable except the mounted data volume.
USER 10001:10001
# Note: a fresh *named* volume inherits this ownership. A host bind mount does
# not — chown it to 10001 on the host or the proxy refuses to boot, loudly.
VOLUME ["/data"]
ENV DATA_DIR=/data \
    PORT=8000 \
    HOST=0.0.0.0
EXPOSE 8000

# The binary probes itself — there is no curl in here to do it with.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/sluice", "--health"]

ENTRYPOINT ["/sluice"]
