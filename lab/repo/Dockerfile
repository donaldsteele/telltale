# The lab's signed third-party APT repository. Context is assembled by
# labkit: this file, build.sh and the prebuilt static binaries repo-server
# (./lab/repo/server) and lab-vendord (./lab/repo/vendord).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gnupg apt-utils \
 && rm -rf /var/lib/apt/lists/*
COPY build.sh lab-vendord /src/
RUN sh /src/build.sh

FROM scratch
COPY --from=build /repo /repo
COPY repo-server /repo-server
LABEL telltale-lab=1
EXPOSE 80
ENTRYPOINT ["/repo-server"]
