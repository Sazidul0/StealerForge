#!/bin/sh
# Send everything leaving the sealed analysis namespace to the local network simulator (netsim.py).
# sfsink0 is a dummy device with no carrier: any packet that is not redirected is dropped, so nothing
# configured here can create a path to a real network.
set -eu
ip link add sfsink0 type dummy
ip addr add 198.19.255.254/32 dev sfsink0
ip link set sfsink0 up
ip route add default dev sfsink0
iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 15080
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 15053
iptables -t nat -S OUTPUT
