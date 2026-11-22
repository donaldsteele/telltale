# Build context is assembled by labkit: common/ and variant.sh.
FROM ubuntu:22.04@sha256:f64b2ffc2f10ab8f8505aa56b2664bd846cbb9df87c7e2532e30f7667021c0e6
COPY common/ /lab/common/
RUN /lab/common/setup.sh ubuntu jammy
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL lab.distro=ubuntu2204 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
