# BPF proof of concept

## Brief Description
This BPF program prints a line in `/sys/kernel/debug/tracing/trace_pipe` for
every `write()` system call whose return value is not the same as the
`count` argument it was called with.

## More documentation coming WIP
