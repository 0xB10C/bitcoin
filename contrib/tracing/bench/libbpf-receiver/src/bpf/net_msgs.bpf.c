// SPDX-License-Identifier: MIT
// Copyright (c) 2025-present The Bitcoin Core developers
//
// Records one event per net:inbound_message / net:outbound_message USDT hit
// into a BPF ring buffer. Small payloads (or none) go through a ring of small
// fixed-size records; larger payloads through a second ring with big records,
// like peer-observer's tiered ring buffers. Events that cannot be reserved
// because a ring is full are counted in `dropped`.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#define MAX_MSG_TYPE_LENGTH 20
#define SMALL_PAYLOAD 64
#define LARGE_PAYLOAD (4 * 1024 * 1024)

struct msg_header {
    u64 ts_ns;
    u64 peer_id;
    u64 msg_size;
    u64 inbound;
    u64 payload_len;
    char msg_type[MAX_MSG_TYPE_LENGTH];
};

struct small_event {
    struct msg_header hdr;
    u8 payload[SMALL_PAYLOAD];
};

struct large_event {
    struct msg_header hdr;
    u8 payload[LARGE_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // overridden from user space before load
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); // overridden from user space before load
} events_large SEC(".maps");

// Set from user space before load; number of payload bytes to copy.
const volatile u32 max_payload = 0;

// Number of events that could not be reserved in a ring buffer.
u64 dropped = 0;

static __always_inline void fill_header(struct msg_header *h, u64 inbound, u64 peer_id, void *msg_type, u64 msg_size, u64 payload_len)
{
    h->ts_ns = bpf_ktime_get_ns();
    h->peer_id = peer_id;
    h->msg_size = msg_size;
    h->inbound = inbound;
    h->payload_len = payload_len;
    bpf_probe_read_user_str(&h->msg_type, sizeof(h->msg_type), msg_type);
}

static __always_inline int handle_message(u64 inbound, u64 peer_id, void *msg_type, u64 msg_size, void *payload)
{
    u64 len = max_payload;
    if (len > LARGE_PAYLOAD) len = LARGE_PAYLOAD;
    if (msg_size < len) len = msg_size;
    if (len <= SMALL_PAYLOAD) {
        struct small_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            __sync_fetch_and_add(&dropped, 1);
            return 0;
        }
        fill_header(&e->hdr, inbound, peer_id, msg_type, msg_size, len);
        if (len > 0) bpf_probe_read_user(&e->payload, len, payload);
        bpf_ringbuf_submit(e, 0);
    } else {
        struct large_event *e = bpf_ringbuf_reserve(&events_large, sizeof(*e), 0);
        if (!e) {
            __sync_fetch_and_add(&dropped, 1);
            return 0;
        }
        fill_header(&e->hdr, inbound, peer_id, msg_type, msg_size, len);
        bpf_probe_read_user(&e->payload, len, payload);
        bpf_ringbuf_submit(e, 0);
    }
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
