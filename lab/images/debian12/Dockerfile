# Build context is assembled by labkit: common/ and variant.sh.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY common/ /lab/common/
RUN /lab/common/setup.sh debian bookworm
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL lab.distro=debian12 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
