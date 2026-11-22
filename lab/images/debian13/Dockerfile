# Build context is assembled by labkit: common/ and variant.sh.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY common/ /lab/common/
RUN /lab/common/setup.sh debian trixie
COPY variant.sh /lab/variant.sh
RUN sh /lab/variant.sh && rm -f /lab/variant.sh
ARG VARIANT=clean
LABEL lab.distro=debian13 lab.variant=$VARIANT
ENTRYPOINT ["/lab/common/entrypoint.sh"]
