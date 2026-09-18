// SPDX-License-Identifier: MIT
// Copyright (c) 2025-present The Bitcoin Core developers
//
// Records one fixed-size event per net:inbound_message / net:outbound_message
// USDT hit into a BPF ring buffer. Events that cannot be reserved because the
// ring buffer is full are counted in `dropped`.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#define MAX_MSG_TYPE_LENGTH 20
#define MAX_PAYLOAD 64

struct msg_event {
    u64 ts_ns;
    u64 peer_id;
    u64 msg_size;
    u64 inbound;
    char msg_type[MAX_MSG_TYPE_LENGTH];
    u8 payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // overridden from user space before load
} events SEC(".maps");

// Set from user space before load; number of payload bytes to copy (<= MAX_PAYLOAD).
const volatile u32 max_payload = 0;

// Number of events that could not be reserved in the ring buffer.
u64 dropped = 0;

static __always_inline int handle_message(u64 inbound, u64 peer_id, void *msg_type, u64 msg_size, void *payload)
{
    struct msg_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }
    e->ts_ns = bpf_ktime_get_ns();
    e->peer_id = peer_id;
    e->msg_size = msg_size;
    e->inbound = inbound;
    bpf_probe_read_user_str(&e->msg_type, sizeof(e->msg_type), msg_type);
    u32 len = max_payload;
    if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
    if (msg_size < len) len = msg_size;
    if (len > 0) bpf_probe_read_user(&e->payload, len, payload);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("usdt")
int BPF_USDT(inbound_message, u64 peer_id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *payload)
{
    return handle_message(1, peer_id, msg_type, msg_size, payload);
}

SEC("usdt")
int BPF_USDT(outbound_message, u64 peer_id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *payload)
{
    return handle_message(0, peer_id, msg_type, msg_size, payload);
}

char LICENSE[] SEC("license") = "GPL";
