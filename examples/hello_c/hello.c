//go:build ignore

#include "common.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 uid;
    u32 pid;
    u8 comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->uid = uid;
    e->pid = tgid;
    bpf_get_current_comm(&e->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
