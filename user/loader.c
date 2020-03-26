#include <bpf/libbpf.h>
#include <bcc/libbpf.h>
#include <stdio.h>
#include "bpf_load.h"

#define ERR_PTR(err)    ((void *)((long)(err)))
#define PTR_ERR(ptr)    ((long)(ptr))
#define IS_ERR(ptr)     ((unsigned long)(ptr) > (unsigned long)(-1000))

int main(int argc, char **argv) {
        struct bpf_object *obj;
	struct bpf_program *prog, *retprog;
        struct bpf_link *link, *retlink;
	struct bpf_map *map;
	int progfd, retprogfd, evfd, err;

        // open and interpret the ELF file. I think this also tries
        // to find and attach probepoints based on the name of the section
        // In my program the sections don't match any of those patters so it
        // issues a warning but continues to return a bpf_object
	obj = bpf_object__open("bpf_program.o");
	if(IS_ERR(obj) || !obj) {
                printf("open test_select_reuseport_kern.o \
                        obj:%p PTR_ERR(obj):%ld\n", obj, PTR_ERR(obj));
                return -1;
        }

        // find a program/function in the ELF object that matches the
        // given section name
        prog = bpf_object__find_program_by_title(obj, "entry_probe");
	if(IS_ERR(prog) || !prog) {
                printf("find program \"entry_probe\" \
                        obj:%p PTR_ERR(obj):%ld\n", prog, PTR_ERR(prog));
                return -1;
        }
        
        // since our section names don't match any of the patterns, it's
        // unable to determine if its a kprobe or something else
        // automatically. the following function explicitly sets the program
        // as a kprobe one
        bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);

        retprog = bpf_object__find_program_by_title(obj, "ret_probe");
	if(IS_ERR(retprog) || !retprog) {
                printf("find program \"ret_probe\" \
                        obj:%p PTR_ERR(obj):%ld\n", retprog, PTR_ERR(retprog));
                return -1;
        }
        bpf_program__set_type(retprog, BPF_PROG_TYPE_KPROBE);

        // load the BPF program into the kernel. need to do this before we
        // can use any of the program filedescriptors
        err = bpf_object__load(obj);
        if(err < 0) {
                libbpf_strerror(err, "bpf_object__load failed", 24);
        }
        
        // retrieve the program filedescriptors, which is then used to
        // refer to the program when attaching it to a kprobe/kretprobe
        progfd = bpf_program__fd(prog);
        retprogfd = bpf_program__fd(retprog);

        if (progfd < 0 || retprogfd < 0) {
                printf("program fd not found: %s\n");
                return -1;
        }

        // attach BPF program to kretprobe. this currently doesn't work when
        // there is kprobe on the same function. libbpf doesn't provid an
        // interface to create an entry handler for a kretprobe. so this
        // will need to be converted to a kprobe API call
        evfd = bpf_attach_kprobe(retprogfd, BPF_PROBE_RETURN, "exit_ksys_write", "ksys_write", 0L, 0);
        if (evfd < 0) {
                printf("attach kprobe \"exit_ksys_write\" failed");
                return -1;
        }

        // attach BPF program to a kprobe with exit_ksys_write event name
        // and ksys_write the function to probe at offset 0L and maxactive =
        // 0
/*        evfd = bpf_attach_kprobe(progfd, BPF_PROBE_ENTRY, "enter_ksys_write", "ksys_write", 0L, 0);
        if (evfd < 0) {
                printf("attach kprobe \"enter_ksys_write\" failed");
                return -1;
        }
        */
        while(1) {
        }
  return 0;
}
