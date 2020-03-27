#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include "bpf_helpers.h"

#define FILTER_EXP (*count != ret)
struct bpf_map_def SEC("maps") proc_arg_map = {
        .type = BPF_MAP_TYPE_HASH,
        .max_entries = 1024,
        .key_size = sizeof(long),
        .value_size = sizeof(long),
}; 

SEC("ret_probe")
int trace_write_ret(struct pt_regs *ctx) {
        long ret = PT_REGS_RC(ctx);
        long *count;
        char msg[] = "count=%ld ret=%ld\n";
        int err;
        u64 pidtgid = bpf_get_current_pid_tgid();

        count = bpf_map_lookup_elem(&proc_arg_map, &pidtgid);
        if(!count) {
                //No element found. I don't think this should happen
                //unless we've lost a kretprobe due to insufficient 
                //maxactive
                return 0;
        }

        if(FILTER_EXP) 
                bpf_trace_printk(msg, sizeof(msg), *count, ret);
        return 0;
}

SEC("entry_probe")
int trace_write_entry(struct pt_regs *ctx) {
        long fd = PT_REGS_PARM1(ctx);
        long count = PT_REGS_PARM3(ctx);
        char msg[] = "fd=%ld count=%ld\n";
        int err;
        u64 pidtgid = bpf_get_current_pid_tgid();
        
        // Create a map element with
        // key = pidtgid
        // value = count that ksys_write was called with
        err = bpf_map_update_elem(&proc_arg_map, &pidtgid, &count, BPF_ANY);
        if (err < 0) {
                return err;        
        }

        return 0;
}

char _license[] SEC("license") = "GPL";
