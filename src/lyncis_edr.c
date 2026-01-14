#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>
#include "lyncis.skel.h"

// Extended event structure to include parent info
struct event {
    unsigned int pid;
    unsigned int ppid; // Parent PID for lineage tracking
    unsigned int uid;
    char comm[16];
    unsigned long long ts;
};

// Function to resolve a PID to its command name (Forensic Enrichment)
void get_cmdline(int pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(buf, size, f)) {
            buf[strcspn(buf, "\n")] = 0; // Remove newline
        }
        fclose(f);
    } else {
        strncpy(buf, "unknown", size);
    }
}

void trigger_forensics(int pid, int ppid, const char *comm) {
    char parent_comm[16];
    char cmd[512];
    
    get_cmdline(ppid, parent_comm, sizeof(parent_comm));
    
    // 1. Freeze the culprit
    kill(pid, SIGSTOP);
    
    printf("\n[🚨 LINEAGE DETECTED]\n");
    printf("PARENT: %s (%d) ---> OFFENDER: %s (%d)\n", parent_comm, ppid, comm, pid);

    // 2. High-speed Memory Carving
    snprintf(cmd, sizeof(cmd), "gcore -o evidence_%s_pid%d %d > /dev/null 2>&1", comm, pid, pid);
    
    if (system(cmd) == 0) {
        printf("[🛡️ FORENSICS] Evidence captured: evidence_%s_pid%d\n", comm, pid);
    }

    // 3. Post-Capture Remediation: Total Neutralization
    printf("[💀] Neutralizing threat. Terminating PID %d...\n", pid);
    kill(pid, SIGKILL); 
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", tm);

    // Advanced JSON Telemetry (SIEM-Ready)
    printf("{\"timestamp\": \"%s\", \"alert\": \"MEMORY_INTEGRITY_VIOLATION\", \"severity\": \"EMERGENCY\", \"process\": {\"name\": \"%s\", \"pid\": %d, \"ppid\": %d}, \"action\": \"BLOCK_AND_CAPTURE\"}\n", 
           time_str, e->comm, e->pid, e->ppid);

    trigger_forensics(e->pid, e->ppid, e->comm);
    return 0;
}

int main() {
    struct lyncis *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Self-elevate memory limits
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = lyncis__open_and_load();
    if (!skel) return 1;

    err = lyncis__attach(skel);
    if (err) goto cleanup;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);

    printf("🛡️ LYNCIS KERNEL GUARD: ELITE EDITION\n");
    printf("[*] Real-time Lineage Tracking: ACTIVE\n");
    printf("[*] Auto-Remediation (SIGKILL): ACTIVE\n");
    printf("------------------------------------------------\n");

    while (1) { ring_buffer__poll(rb, 100); }

cleanup:
    lyncis__destroy(skel);
    return 0;
}
