# BPF proof of concept

## Brief Description
This BPF program prints a line in `/sys/kernel/debug/tracing/trace_pipe` for
every `write()` system call whose return value is not the same as the
`count` argument it was called with.

## Development Environment
All code has been developed in the Vagrant box found
[here](https://github.com/bpftools/linux-observability-with-bpf). The
current state of the code requires kernel sources to be present.

## Reading/Reference Material
I found [this book]() (free after registering) to be good introduction, and the
Vagrant image is also from the book. There are various APIs that is probably
not documented in the book (I haven't read it all), like libbpf.

## More documentation coming. very much a  WIP
