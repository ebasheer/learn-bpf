#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include "bpf_helpers.h"

SEC("ret_probe")
int trace_write_ret(struct pt_regs *ctx) {
        long ret = PT_REGS_RET(ctx);
        char msg[] = "ret=%ld\n";
        bpf_trace_printk(msg, sizeof(msg), ret);
        return 0;
}

SEC("entry_probe")
int trace_write_entry(struct pt_regs *ctx) {
        long fd = PT_REGS_PARM1(ctx);
        long count = PT_REGS_PARM3(ctx);
        char msg[] = "fd=%ld count=%ld\n";
        bpf_trace_printk(msg, sizeof(msg), fd, count);
        return 0;
}

char _license[] SEC("license") = "GPL";
