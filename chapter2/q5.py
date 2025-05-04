# You could further adapt hello_map.py so that the key in the hash table identifies a
# particular syscall (rather than a particular user). The output will show how many
# times that syscall has been called across the whole system.

#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table, u64, u64);

RAW_TRACEPOINT_PROBE(sys_enter) {
    u64 syscall_id = ctx->args[1];  // syscall number
    u64 zero = 0, *count;

    count = counter_table.lookup_or_init(&syscall_id, &zero);
    (*count)++;

    return 0;
}
"""

b = BPF(text=program)

print("Counting syscalls by syscall number... Hit Ctrl-C to stop.\n")

while True:
    sleep(2)
    print("Syscall counts:")
    for k, v in b["counter_table"].items():
        print(f"Syscall #{k.value}: {v.value}")
    print("-" * 30)

