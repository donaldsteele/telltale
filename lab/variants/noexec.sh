#!/bin/sh
# The image itself is the plain one. This variant is about how it is run:
#   docker run --tmpfs /tmp:noexec --tmpfs /dev/shm:noexec ...
# labkit.Start adds those flags when Opts.Noexec is set (or the image's lab.variant label is noexec).
true
