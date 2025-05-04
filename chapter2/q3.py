# The hello-tail.py eBPF program is an example of a program that attaches to the
# sys_enter raw tracepoint that is hit whenever any syscall is called. Change hello-
# map.py to show the total number of syscalls made by each user ID, by attaching it
# to that same sys_enter raw tracepoint.
# Here’s some example output I got after making that change:
# $ ./hello-map.py
# ID 104: 6
# ID 0: 225
# ID 104: 6
# ID 101: 34
# ID 104: 6
# ID 101: 34
# ID 104: 6
# ID 101: 34
# ID 100: 45
# ID 100: 45
# ID 100: 45
# ID 0: 332
# ID 0: 368
# ID 0: 533
# ID 501: 19
# ID 501: 38
# ID 501: 57

#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int count_syscalls(struct bpf_raw_tracepoint_args *ctx) {
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
"""

b = BPF(text=program)

b.attach_raw_tracepoint(tp="sys_enter", fn_name="count_syscalls")

print("Tracing all syscalls by UID... Hit Ctrl-C to stop.")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\n"
    if s:
        print(s)

