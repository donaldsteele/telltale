# Build context is assembled by labkit: common/ and variant.sh.
FROM ubuntu:22.04@sha256:f64b2ffc2f10ab8f8505aa56b2664bd846cbb9df87c7e2532e30f7667021c0e6
COPY common/ /lab/common/
# LAB_NEWER=1 builds at the newer package snapshot; LAB_SYSTEMD=1 adds systemd.
ARG LAB_NEWER=0
ARG LAB_SYSTEMD=0
RUN LAB_NEWER=$LAB_NEWER LAB_SYSTEMD=$LAB_SYSTEMD /lab/common/setup.sh ubuntu jammy
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL telltale-lab=1 lab.distro=ubuntu2204 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
