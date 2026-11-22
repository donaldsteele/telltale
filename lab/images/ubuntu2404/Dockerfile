# Build context is assembled by labkit: common/ and variant.sh.
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
COPY common/ /lab/common/
RUN /lab/common/setup.sh ubuntu noble
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL lab.distro=ubuntu2404 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
