#include <linux/atomic.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/ptrace.h>

SEC("kprobe/sys_write")
int bpf_prog(struct pt_regs *ctx) {
  long fd = PT_REGS_PARM1(ctx);
  long count = PT_REGS_PARM3(ctx);
  char msg[] = "fd=%d count=%d\n";
  bpf_trace_printk(msg, sizeof(msg), fd, count);
  return 0;
}

char _license[] SEC("license") = "GPL";
