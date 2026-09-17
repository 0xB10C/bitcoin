// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/handler.h>
#include <interfaces/tracing.h>
#include <node/net_trace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

void Record(NetMessageTracer& tracer, bool inbound, const std::string& type, size_t payload_len, int64_t peer = 7)
{
    std::vector<unsigned char> payload(payload_len, 0xab);
    tracer.record(inbound, peer, "127.0.0.1:1234", "inbound", type, payload);
}

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
