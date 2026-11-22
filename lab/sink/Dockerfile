# Context holds the prebuilt static binary named "sink":
#   CGO_ENABLED=0 go build -tags lab -o sink ./lab/sink
FROM scratch
COPY sink /sink
EXPOSE 4444 8443
ENTRYPOINT ["/sink"]
