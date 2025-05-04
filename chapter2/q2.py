# Modify hello-map.py so that the eBPF code gets triggered by more than one
# syscall. For example, openat() is commonly called to open files, and write() is
# called to write data to a file. You can start by attaching the hello eBPF program to
# multiple syscall kprobes. Then try having modified versions of the hello eBPF
# program for different syscalls, demonstrating that you can access the same map
# from multiple different programs.

#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int count_execve(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 counter = 0;
    u64 *p = counter_table.lookup(&uid);
    if (p) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);
    return 0;
}

int count_openat(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 counter = 0;
    u64 *p = counter_table.lookup(&uid);
    if (p) {
        counter = *p;
    }
    counter += 10;  // distinguish openat calls
    counter_table.update(&uid, &counter);
    return 0;
}

int count_write(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 counter = 0;
    u64 *p = counter_table.lookup(&uid);
    if (p) {
        counter = *p;
    }
    counter += 100;  // distinguish write calls
    counter_table.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text=program)

b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="count_execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="count_openat")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="count_write")

print("Tracing syscalls... Hit Ctrl-C to end.")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"UID {k.value}: Count {v.value}\t"
    print(s)

