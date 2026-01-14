#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// MUST MATCH YOUR USER-SPACE STRUCT EXACTLY
struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("lsm/file_mprotect")
int BPF_PROG(lyncis_mprotect_guard, struct vm_area_struct *vma, 
             unsigned long reqprot, unsigned long prot, int ret) 
{
    // Ignore if already denied by another security module
    if (ret != 0) return ret;

    // Detection Logic: Block attempts to make memory Executable (0x04)
    if (prot & 0x04) { 
        struct event *e;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return -1; 

        // Identity Tracking
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid();
        e->ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // Beyond CIA: Lineage Tracking
        // We reach into the task_struct to find the real_parent's PID
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);

        bpf_ringbuf_submit(e, 0);
        
        // VETO: Return Operation Not Permitted to the system
        return -1; 
    }
    return 0;
}
