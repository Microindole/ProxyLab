FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS builder

ARG SSR_COMMIT=17677abc3c3c0992244b732c7b62397022dbbe79

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential ca-certificates cmake git \
    && git clone --recursive https://github.com/ShadowsocksR-Live/shadowsocksr-native.git /src \
    && cd /src \
    && git checkout --detach "${SSR_COMMIT}" \
    && git submodule update --init --recursive \
    && cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /src/build --parallel 2 \
    && install -D /src/build/src/ssr-server /out/usr/local/bin/ssr-server \
    && install -D /src/build/src/ssr-client /out/usr/local/bin/ssr-client

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

COPY --from=builder /out/ /

USER 65532:65532

ENTRYPOINT []
CMD ["ssr-server", "-h"]
