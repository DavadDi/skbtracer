#!/usr/bin/python
from bcc import BPF

prog = """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>

#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
    })
#define member_read(destination, source_struct, source_member)  \
  do{                                                           \
    bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
    );                                                          \
  } while(0)

struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    u64 start_ns;
};

BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };

    args.start_ns = bpf_ktime_get_ns();
    cur_ipt_do_table_args.update(&pid, &args);

    return 0;
};

struct event_data_t {
    void  *skb;
    u32 pid;
    u32 hook;
    u32 verdict;
    u8  pf;
    u8  reserv[3];
    char table[XT_TABLE_MAXNAMELEN];
};

BPF_PERF_OUTPUT(open_events);

/*
 * tricky: use ebx as the 1st parms, thus get skb
 */
int kretprobe__ipt_do_table(struct pt_regs *ctx)
{
    struct ipt_do_table_args *args;
    u32 pid = bpf_get_current_pid_tgid();
    struct event_data_t evt = {};

    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
        return 0;

    cur_ipt_do_table_args.delete(&pid);

    evt.pid = pid;
    evt.skb = args->skb;
    member_read(&evt.hook, args->state, hook);
    //member_read(&evt.pf, args->state, pf);
    member_read(&evt.table, args->table, name);
    evt.verdict = PT_REGS_RC(ctx);

    open_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

"""

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default

def print_event(cpu, data, size):
  event = b["open_events"].event(data)

  hook    = _get(HOOKNAMES, event.hook, "~UNK~")
  verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")

  print("%-10d %-16x  %-12s %-12s %-10s"%(event.pid, event.skb, event.table, hook, verdict))

b = BPF(text=prog)
b["open_events"].open_perf_buffer(print_event)

print("pid skb_addr table  hook verdict")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

