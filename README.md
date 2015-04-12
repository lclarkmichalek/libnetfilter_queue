libnetfilter_queue
==================

This is a rust binding for libnetfilter_queue, a Linux library that allows
userspace to make decisions on the destiny of packets.

Note: cargo test will fail unless run as root on a linux system with the
`nfnetlink_queue` module loaded.
