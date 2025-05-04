# The RAW_TRACEPOINT_PROBE macro provided by BCC simplifies attaching to raw
# tracepoints, telling the user space BCC code to automatically attach it to a speci‐
# fied tracepoint. Try it in hello-tail.py, like this:
# • Replace the definition of the hello() function with RAW_TRACE
# POINT_PROBE(sys_enter).
# • Remove the explicit attachment call b.attach_raw_tracepoint() from the
# Python code.
# You should see that BCC automatically creates the attachment and the program
# works exactly the same. This is an example of the many convenient macros that
# BCC provides.

#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

RAW_TRACEPOINT_PROBE(sys_enter) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text=program)

print("Tracing syscalls by UID using RAW_TRACEPOINT_PROBE... Hit Ctrl-C to stop.")

while True:
    sleep(2)
    output = ""
    for k, v in b["counter_table"].items():
        output += f"ID {k.value}: {v.value}\n"
    if output:
        print(output)

