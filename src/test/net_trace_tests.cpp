// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/handler.h>
#include <interfaces/tracing.h>
#include <node/net_trace.h>
#include <test/util/setup_common.h>
#include <util/shared_memory.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

using interfaces::NetMessageInfo;
using interfaces::NetMessageTraceOptions;
using node::NetMessageTracer;

namespace {

//! Collects delivered batches. Optionally blocks the delivery thread on the
//! first batch until Release() is called, so tests can fill the queue.
class CollectingTrace : public interfaces::NetMessageTrace
{
public:
    explicit CollectingTrace(bool block_first = false) : m_block_first{block_first} {}

    void messages(const std::vector<NetMessageInfo>& messages, uint64_t dropped) override
    {
        std::unique_lock lock{m_mutex};
        m_batches.push_back(messages);
        m_dropped += dropped;
        m_delivered += messages.size();
        m_cv.notify_all();
        if (m_block_first && !m_released) {
            m_blocked = true;
            m_cv.notify_all();
            m_cv.wait(lock, [this] { return m_released; });
        }
    }

    void Release()
    {
        std::lock_guard lock{m_mutex};
        m_released = true;
        m_cv.notify_all();
    }

    void WaitBlocked()
    {
        std::unique_lock lock{m_mutex};
        BOOST_REQUIRE(m_cv.wait_for(lock, std::chrono::seconds{10}, [this] { return m_blocked; }));
    }

    void WaitDelivered(size_t n)
    {
        std::unique_lock lock{m_mutex};
        BOOST_REQUIRE(m_cv.wait_for(lock, std::chrono::seconds{10}, [this, n] { return m_delivered >= n; }));
    }

    size_t Delivered()
    {
        std::lock_guard lock{m_mutex};
        return m_delivered;
    }
    uint64_t Dropped()
    {
        std::lock_guard lock{m_mutex};
        return m_dropped;
    }
    std::vector<std::vector<NetMessageInfo>> Batches()
    {
        std::lock_guard lock{m_mutex};
        return m_batches;
    }

private:
    const bool m_block_first;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::vector<NetMessageInfo>> m_batches;
    size_t m_delivered{0};
    uint64_t m_dropped{0};
    bool m_blocked{false};
    bool m_released{false};
};

class ThrowingTrace : public interfaces::NetMessageTrace
{
public:
    void messages(const std::vector<NetMessageInfo>&, uint64_t) override
    {
        m_called.set_value();
        throw std::runtime_error{"client gone"};
    }
    std::promise<void> m_called;
};

void Record(NetMessageTracer& tracer, bool inbound, const std::string& type, size_t payload_len, int64_t peer = 7,
            unsigned char fill = 0xab)
{
    std::vector<unsigned char> payload(payload_len, fill);
    tracer.record(inbound, peer, "127.0.0.1:1234", "inbound", type, payload);
}

//! Maps the shared payload arena and resolves every event's payload bytes from
//! it, the way an out-of-process subscriber does.
class ArenaTrace : public interfaces::NetMessageTrace
{
public:
    void payloadArena(const std::string& name, uint64_t slot_bytes, uint32_t slot_count) override
    {
        std::string error;
        m_arena = util::SharedMemory::Open(name, slot_bytes * slot_count, error);
        BOOST_REQUIRE_MESSAGE(m_arena, error);
        m_slot_bytes = slot_bytes;
        m_slot_count = slot_count;
    }

    void messages(const std::vector<NetMessageInfo>& messages, uint64_t dropped) override
    {
        std::lock_guard lock{m_mutex};
        m_dropped += dropped;
        for (const auto& m : messages) {
            std::vector<unsigned char> payload;
            if (m.payload_slot >= 0) {
                BOOST_REQUIRE(m_arena);
                BOOST_REQUIRE(static_cast<uint32_t>(m.payload_slot) < m_slot_count);
                BOOST_REQUIRE(m.payload_len <= m_slot_bytes);
                const auto* base{reinterpret_cast<const unsigned char*>(m_arena.data())};
                base += static_cast<uint64_t>(m.payload_slot) * m_slot_bytes;
                payload.assign(base, base + m.payload_len);
            } else {
                payload = m.payload;
            }
            m_events.emplace_back(m.msg_type, m.payload_slot, std::move(payload));
        }
    }

    struct Event {
        std::string type;
        int32_t slot;
        std::vector<unsigned char> payload;
    };
    std::vector<Event> Events()
    {
        std::lock_guard lock{m_mutex};
        return m_events;
    }
    uint64_t Dropped()
    {
        std::lock_guard lock{m_mutex};
        return m_dropped;
    }
    void WaitEvents(size_t n)
    {
        for (int i = 0; i < 1000; ++i) {
            {
                std::lock_guard lock{m_mutex};
                if (m_events.size() >= n) return;
            }
            UninterruptibleSleep(std::chrono::milliseconds{10});
        }
        BOOST_FAIL("timed out waiting for events");
    }

private:
    util::SharedMemory m_arena;
    uint64_t m_slot_bytes{0};
    uint32_t m_slot_count{0};
    std::mutex m_mutex;
    std::vector<Event> m_events;
    uint64_t m_dropped{0};
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_trace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(subscribe_and_deliver)
{
    NetMessageTracer tracer;
    BOOST_CHECK(!tracer.active());
    BOOST_CHECK_EQUAL(tracer.subscriberCount(), 0U);

    auto trace{std::make_unique<CollectingTrace>()};
    auto* trace_ptr{trace.get()};
    NetMessageTraceOptions opts;
    opts.max_payload_bytes = 4;
    auto handler{tracer.subscribe(opts, std::move(trace))};
    BOOST_CHECK(tracer.active());
    BOOST_CHECK_EQUAL(tracer.subscriberCount(), 1U);

    Record(tracer, /*inbound=*/true, "ping", 8);
    Record(tracer, /*inbound=*/false, "pong", 8, /*peer=*/9);
    trace_ptr->WaitDelivered(2);

    std::vector<NetMessageInfo> all;
    for (const auto& batch : trace_ptr->Batches()) all.insert(all.end(), batch.begin(), batch.end());
    BOOST_REQUIRE_EQUAL(all.size(), 2U);
    BOOST_CHECK(all[0].inbound);
    BOOST_CHECK_EQUAL(all[0].peer_id, 7);
    BOOST_CHECK_EQUAL(all[0].peer_addr, "127.0.0.1:1234");
    BOOST_CHECK_EQUAL(all[0].conn_type, "inbound");
    BOOST_CHECK_EQUAL(all[0].msg_type, "ping");
    BOOST_CHECK_EQUAL(all[0].msg_size, 8U);
    BOOST_CHECK_EQUAL(all[0].payload.size(), 4U); // truncated to max_payload_bytes
    BOOST_CHECK(all[0].timestamp_us > 0);
    BOOST_CHECK(!all[1].inbound);
    BOOST_CHECK_EQUAL(all[1].peer_id, 9);
    BOOST_CHECK_EQUAL(all[1].msg_type, "pong");
    BOOST_CHECK_EQUAL(trace_ptr->Dropped(), 0U);

    handler.reset();
    BOOST_CHECK(!tracer.active());
    BOOST_CHECK_EQUAL(tracer.subscriberCount(), 0U);
}

BOOST_AUTO_TEST_CASE(direction_filter_and_payload_cap)
{
    NetMessageTracer tracer;
    auto trace{std::make_unique<CollectingTrace>()};
    auto* trace_ptr{trace.get()};
    NetMessageTraceOptions opts;
    opts.inbound = false;
    opts.max_payload_bytes = 0;
    auto handler{tracer.subscribe(opts, std::move(trace))};

    Record(tracer, /*inbound=*/true, "ping", 8);
    Record(tracer, /*inbound=*/true, "ping", 8);
    Record(tracer, /*inbound=*/false, "pong", 8);
    trace_ptr->WaitDelivered(1);
    // Give any spurious inbound delivery a chance to show up.
    UninterruptibleSleep(std::chrono::milliseconds{50});
    auto batches{trace_ptr->Batches()};
    BOOST_REQUIRE_EQUAL(trace_ptr->Delivered(), 1U);
    BOOST_CHECK(!batches[0][0].inbound);
    BOOST_CHECK_EQUAL(batches[0][0].msg_size, 8U);
    BOOST_CHECK(batches[0][0].payload.empty());
}

BOOST_AUTO_TEST_CASE(bounded_queue_drops_and_batches)
{
    NetMessageTracer tracer;
    auto trace{std::make_unique<CollectingTrace>(/*block_first=*/true)};
    auto* trace_ptr{trace.get()};
    NetMessageTraceOptions opts;
    opts.max_queue_events = 4;
    opts.max_batch_events = 3;
    auto handler{tracer.subscribe(opts, std::move(trace))};

    // First event wakes the delivery thread, which blocks inside messages().
    Record(tracer, true, "ping", 0);
    trace_ptr->WaitBlocked();
    // Queue is now empty (first event was taken). Fill it past capacity.
    for (int i = 0; i < 10; ++i) Record(tracer, true, "ping", 0);
    trace_ptr->Release();
    trace_ptr->WaitDelivered(1 + 4);
    UninterruptibleSleep(std::chrono::milliseconds{50});

    BOOST_CHECK_EQUAL(trace_ptr->Delivered(), 5U);
    BOOST_CHECK_EQUAL(trace_ptr->Dropped(), 6U);
    BOOST_CHECK_EQUAL(trace_ptr->Delivered() + trace_ptr->Dropped(), 11U);
    for (const auto& batch : trace_ptr->Batches()) BOOST_CHECK(batch.size() <= 3);
}

BOOST_AUTO_TEST_CASE(shared_memory_payload_arena)
{
    NetMessageTracer tracer;
    auto trace{std::make_unique<ArenaTrace>()};
    auto* trace_ptr{trace.get()};
    NetMessageTraceOptions opts;
    opts.max_payload_bytes = 64 * 1024;
    opts.shm_bytes = 4 * 1024 * 1024; // 64 slots of 64 KiB
    opts.shm_min_payload_bytes = 4096;
    opts.max_batch_wait_us = 0;
    auto handler{tracer.subscribe(opts, std::move(trace))};

    // The arena is only used after the subscriber has been told about it.
    for (int i = 0; i < 1000 && trace_ptr->Events().empty(); ++i) {
        Record(tracer, /*inbound=*/true, "ping", 10000, /*peer=*/7, /*fill=*/0x11);
        UninterruptibleSleep(std::chrono::milliseconds{1});
    }
    trace_ptr->WaitEvents(1);
    // Small payloads stay inline, large ones go through the arena. Send both
    // several times so that arena slots are reused after delivery.
    for (int i = 0; i < 100; ++i) {
        Record(tracer, /*inbound=*/true, "small", 100, /*peer=*/7, /*fill=*/0x22);
        Record(tracer, /*inbound=*/true, "big", 10000, /*peer=*/7, /*fill=*/0x33);
        UninterruptibleSleep(std::chrono::milliseconds{1});
    }

    size_t small{0}, big{0};
    for (int i = 0; i < 500 && (small < 100 || big < 100); ++i) {
        small = big = 0;
        for (const auto& e : trace_ptr->Events()) {
            if (e.type == "small") ++small;
            if (e.type == "big") ++big;
        }
        if (small < 100 || big < 100) UninterruptibleSleep(std::chrono::milliseconds{10});
    }
    BOOST_CHECK_EQUAL(trace_ptr->Dropped(), 0U);
    BOOST_CHECK_EQUAL(small, 100U);
    BOOST_CHECK_EQUAL(big, 100U);
    for (const auto& e : trace_ptr->Events()) {
        if (e.type == "small") {
            BOOST_CHECK_EQUAL(e.slot, -1);
            BOOST_CHECK_EQUAL(e.payload.size(), 100U);
            BOOST_CHECK(std::ranges::all_of(e.payload, [](unsigned char c) { return c == 0x22; }));
        } else if (e.type == "big") {
            BOOST_CHECK(e.slot >= 0);
            BOOST_CHECK_EQUAL(e.payload.size(), 10000U);
            BOOST_CHECK(std::ranges::all_of(e.payload, [](unsigned char c) { return c == 0x33; }));
        }
    }
    handler.reset();
}

BOOST_AUTO_TEST_CASE(throwing_callback_removes_subscriber)
{
    NetMessageTracer tracer;
    auto trace{std::make_unique<ThrowingTrace>()};
    auto called{trace->m_called.get_future()};
    auto handler{tracer.subscribe(NetMessageTraceOptions{}, std::move(trace))};
    BOOST_CHECK(tracer.active());

    Record(tracer, true, "ping", 0);
    BOOST_REQUIRE(called.wait_for(std::chrono::seconds{10}) == std::future_status::ready);
    // The delivery thread removes the subscriber on failure.
    for (int i = 0; i < 100 && tracer.active(); ++i) UninterruptibleSleep(std::chrono::milliseconds{10});
    BOOST_CHECK(!tracer.active());
    BOOST_CHECK_EQUAL(tracer.subscriberCount(), 0U);
    // Recording with no subscribers is a no-op, and resetting the handler is safe.
    Record(tracer, true, "ping", 0);
    handler.reset();
    BOOST_CHECK_EQUAL(tracer.subscriberCount(), 0U);
}

BOOST_AUTO_TEST_CASE(destroy_tracer_with_live_subscriber)
{
    std::unique_ptr<interfaces::Handler> handler;
    {
        NetMessageTracer tracer;
        auto trace{std::make_unique<CollectingTrace>()};
        auto* trace_ptr{trace.get()};
        handler = tracer.subscribe(NetMessageTraceOptions{}, std::move(trace));
        Record(tracer, true, "ping", 0);
        trace_ptr->WaitDelivered(1);
        // tracer destroyed here while the subscription is still held.
    }
    // Handler cleanup after the tracer is gone must be harmless.
    handler.reset();
    // Handler disconnect() after reset-order variations must also be harmless.
    NetMessageTracer tracer2;
    auto handler2{tracer2.subscribe(NetMessageTraceOptions{}, std::make_unique<CollectingTrace>())};
    handler2->disconnect();
    BOOST_CHECK(!tracer2.active());
    handler2.reset();
}

BOOST_AUTO_TEST_SUITE_END()
