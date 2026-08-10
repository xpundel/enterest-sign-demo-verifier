# syntax=docker/dockerfile:1

ARG CRYPTOPRO_BASE_IMAGE=cryptopro-csp:5.0

FROM ${CRYPTOPRO_BASE_IMAGE} AS cryptopro
USER root
ARG CRYPTOPRO_CADES_PACKAGE=cprocsp-pki-cades-64
RUN dpkg-query -W "$CRYPTOPRO_CADES_PACKAGE" >/dev/null 2>&1 || \
    (apt-get update && apt-get install -y --no-install-recommends "$CRYPTOPRO_CADES_PACKAGE" && rm -rf /var/lib/apt/lists/*)
RUN test -f /opt/cprocsp/include/pki/cades.h && \
    test -f /opt/cprocsp/lib/amd64/libcades.so

FROM scratch AS test-ca
ADD --checksum=sha256:8f217cb5a025647364c00d60ff77444e7cdb7005b26f264f056b9a661130204e \
    https://testca.cryptopro.ru/CertEnroll/test-ca-2014_CRYPTO-PRO%20Test%20Center%202%284%29.crt \
    /cryptopro-test-center-2.crt

FROM cryptopro AS cryptopro-runtime
ARG INCLUDE_TEST_CA=true
RUN --mount=type=bind,from=test-ca,source=/cryptopro-test-center-2.crt,target=/tmp/cryptopro-test-center-2.crt \
    if [ "$INCLUDE_TEST_CA" = "true" ]; then \
      /opt/cprocsp/bin/amd64/certmgr -install -store mRoot -file /tmp/cryptopro-test-center-2.crt; \
    fi
LABEL verifier.cryptopro-test-ca-included="${INCLUDE_TEST_CA}"

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY --from=cryptopro /opt/cprocsp /opt/cprocsp
COPY go.mod *.go ./
COPY native/cades_verify.c ./native/cades_verify.c
RUN mkdir -p /out && \
    cc -std=c11 -O2 -DLINUX -DSIZEOF_VOID_P=8 \
      -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki \
      -L/opt/cprocsp/lib/amd64 -Wl,-rpath,/opt/cprocsp/lib/amd64 \
      -o /out/cades-verify native/cades_verify.c -lcades -lcapi20 -lrdrsup -lpthread && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/signature-verifier .

FROM cryptopro-runtime
COPY --from=build /out/signature-verifier /usr/local/bin/signature-verifier
COPY --from=build /out/cades-verify /usr/local/bin/cades-verify
ENV LISTEN_ADDR=:8080 \
    CADES_HELPER_PATH=/usr/local/bin/cades-verify \
    VERIFY_TIMEOUT=30s \
    MAX_DOCUMENT_BYTES=26214400 \
    MAX_SIGNATURE_BYTES=5242880 \
    HOME=/tmp

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/signature-verifier"]
