#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include "bpf_helpers.h"

SEC("kprobe/ksys_write")
int bpf_prog(struct pt_regs *ctx) {
  long fd = PT_REGS_PARM1(ctx);
  long count = PT_REGS_PARM3(ctx);
  char msg[] = "fd=%ld count=%ld\n";
  bpf_trace_printk(msg, sizeof(msg), fd, count);
  return 0;
}

char _license[] SEC("license") = "GPL";
