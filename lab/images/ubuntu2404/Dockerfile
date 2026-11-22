# Build context is assembled by labkit: common/ and variant.sh.
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
COPY common/ /lab/common/
# LAB_NEWER=1 builds at the newer package snapshot; LAB_SYSTEMD=1 adds systemd.
ARG LAB_NEWER=0
ARG LAB_SYSTEMD=0
RUN LAB_NEWER=$LAB_NEWER LAB_SYSTEMD=$LAB_SYSTEMD /lab/common/setup.sh ubuntu noble
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL telltale-lab=1 lab.distro=ubuntu2404 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
