// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Rust client for the Bitcoin Core IPC tracing interface, modeled on
//! peer-observer's ipc-extractor (capnp-rpc over a unix socket). Subscribes to
//! P2P message events with `Tracing.traceNetMessages` and counts them straight
//! from the Cap'n Proto readers, without copying events into owned structs.
//!
//! Same per-second stats and JSON summary as `bitcoin-trace -stats -json`, so
//! `run_bench.py --mode ipc --ipc-client rust` can drive it.
//!
//! The node delivers batches by calling back into this process. For that it
//! creates a thread handle on our side via the ThreadMap we hand it in
//! `Init.construct`, so this client implements `ThreadMap` and `Thread` too.

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use std::time::{Duration, Instant};

use capnp::Error;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use futures::AsyncReadExt;
use tokio::net::UnixStream;

capnp::generated_code!(pub mod common_capnp);
capnp::generated_code!(pub mod echo_capnp);
capnp::generated_code!(pub mod handler_capnp);
capnp::generated_code!(pub mod init_capnp);
capnp::generated_code!(pub mod mining_capnp);
capnp::generated_code!(pub mod proxy_capnp);
capnp::generated_code!(pub mod rpc_capnp);
capnp::generated_code!(pub mod tracing_capnp);

use proxy_capnp::{thread, thread_map};
use tracing_capnp::net_message_trace;

#[derive(Default, Clone, Copy)]
struct Counters {
    events: u64,
    events_in: u64,
    events_out: u64,
    ping_in: u64,
    pong_out: u64,
    bytes: u64,
    dropped: u64,
    batches: u64,
    lat_sum_us: u64,
    lat_max_us: u64,
}

impl Counters {
    fn add(&mut self, o: &Counters) {
        self.events += o.events;
        self.events_in += o.events_in;
        self.events_out += o.events_out;
        self.ping_in += o.ping_in;
        self.pong_out += o.pong_out;
        self.bytes += o.bytes;
        self.dropped += o.dropped;
        self.batches += o.batches;
        self.lat_sum_us += o.lat_sum_us;
        self.lat_max_us = self.lat_max_us.max(o.lat_max_us);
    }

    fn to_json(self, seconds: f64) -> String {
        let mean = if self.events > 0 {
            self.lat_sum_us as f64 / self.events as f64
        } else {
            0.0
        };
        let rate = if seconds > 0.0 {
            self.events as f64 / seconds
        } else {
            0.0
        };
        format!(
            "\"events\":{},\"events_in\":{},\"events_out\":{},\"ping_in\":{},\"pong_out\":{},\"bytes\":{},\"dropped\":{},\"batches\":{},\"duration_s\":{},\"events_per_s\":{},\"latency_us\":{{\"mean\":{},\"max\":{}}}",
            self.events, self.events_in, self.events_out, self.ping_in, self.pong_out, self.bytes, self.dropped,
            self.batches, seconds, rate, mean, self.lat_max_us
        )
    }
}

fn monotonic_us() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain libc call with a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1000
}

/// Thread handle the node references when it calls back into us.
struct ThreadImpl {
    name: String,
}

impl thread::Server for ThreadImpl {
    async fn get_name(
        self: Rc<Self>,
        _params: thread::GetNameParams,
        mut results: thread::GetNameResults,
    ) -> Result<(), Error> {
        results.get().set_result(&self.name);
        Ok(())
    }
}

/// Lets the node create thread handles on our side (one per node thread that
/// calls into us). We have a single event loop, so the handles are just names.
struct ThreadMapImpl;

impl thread_map::Server for ThreadMapImpl {
    async fn make_thread(
        self: Rc<Self>,
        params: thread_map::MakeThreadParams,
        mut results: thread_map::MakeThreadResults,
    ) -> Result<(), Error> {
        let name = params.get()?.get_name()?.to_string()?;
        results
            .get()
            .set_result(capnp_rpc::new_client(ThreadImpl { name }));
        Ok(())
    }

    async fn make_pool(
        self: Rc<Self>,
        _params: thread_map::MakePoolParams,
        _results: thread_map::MakePoolResults,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// The callback the node delivers batches to.
struct TraceImpl {
    interval: Rc<RefCell<Counters>>,
}

impl net_message_trace::Server for TraceImpl {
    async fn destroy(
        self: Rc<Self>,
        _params: net_message_trace::DestroyParams,
        _results: net_message_trace::DestroyResults,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn messages(
        self: Rc<Self>,
        params: net_message_trace::MessagesParams,
        _results: net_message_trace::MessagesResults,
    ) -> Result<(), Error> {
        let now_us = monotonic_us();
        let p = params.get()?;
        let list = p.get_messages()?;
        let mut c = self.interval.borrow_mut();
        c.batches += 1;
        c.dropped += p.get_dropped();
        for m in list.iter() {
            c.events += 1;
            c.bytes += m.get_msg_size();
            let lat = (now_us - m.get_timestamp_us()).max(0) as u64;
            c.lat_sum_us += lat;
            c.lat_max_us = c.lat_max_us.max(lat);
            let msg_type = m.get_msg_type()?.as_bytes();
            if m.get_inbound() {
                c.events_in += 1;
                if msg_type == b"ping" {
                    c.ping_in += 1;
                }
            } else {
                c.events_out += 1;
                if msg_type == b"pong" {
                    c.pong_out += 1;
                }
            }
        }
        Ok(())
    }
}

struct Args {
    socket: PathBuf,
    payload: u32,
    queue: u32,
    batch: u32,
    batchwait: u32,
    duration: f64,
    out: Option<PathBuf>,
    json: bool,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: net-msgs-ipc --socket <node.sock> [--payload <bytes>] [--queue <events>] [--batch <events>] \
         [--batchwait <us>] [--duration <s>] [--out <f>] [--json] [--quiet]"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        socket: PathBuf::new(),
        payload: 0,
        queue: 65536,
        batch: 1024,
        batchwait: 1000,
        duration: 0.0,
        out: None,
        json: false,
        quiet: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--socket" => args.socket = PathBuf::from(value()),
            "--payload" => args.payload = value().parse().unwrap_or_else(|_| usage()),
            "--queue" => args.queue = value().parse().unwrap_or_else(|_| usage()),
            "--batch" => args.batch = value().parse().unwrap_or_else(|_| usage()),
            "--batchwait" => args.batchwait = value().parse().unwrap_or_else(|_| usage()),
            "--duration" => args.duration = value().parse().unwrap_or_else(|_| usage()),
            "--out" => args.out = Some(PathBuf::from(value())),
            "--json" => args.json = true,
            "--quiet" => args.quiet = true,
            // Accepted for command line compatibility with the eBPF receivers.
            "--ready-file" | "--stop-file" | "--pid" | "--page-cnt" => {
                value();
            }
            _ => usage(),
        }
    }
    if args.socket.as_os_str().is_empty() {
        usage();
    }
    args
}

fn set_context(
    mut ctx: proxy_capnp::context::Builder<'_>,
    thread: &thread::Client,
    callback_thread: &thread::Client,
) {
    ctx.set_thread(thread.clone());
    ctx.set_callback_thread(callback_thread.clone());
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(&args.socket).await?;
    let (reader, writer) = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
    let network = Box::new(twoparty::VatNetwork::new(
        reader,
        writer,
        rpc_twoparty_capnp::Side::Client,
        Default::default(),
    ));
    let mut rpc_system = RpcSystem::new(network, None);
    let init: init_capnp::init::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
    let rpc_task = tokio::task::spawn_local(rpc_system);

    // Exchange thread maps: the node gets ours so it can create thread handles
    // on our side for its callbacks; we get the node's to create a server
    // thread for our own requests.
    let mut req = init.construct_request();
    req.get()
        .set_thread_map(capnp_rpc::new_client(ThreadMapImpl));
    let response = req.send().promise.await?;
    let remote_thread_map = response.get()?.get_thread_map()?;
    let mut req = remote_thread_map.make_thread_request();
    req.get().set_name("net-msgs-ipc");
    let response = req.send().promise.await?;
    let remote_thread = response.get()?.get_result()?;
    let local_thread: thread::Client = capnp_rpc::new_client(ThreadImpl {
        name: "net-msgs-ipc".into(),
    });

    let mut req = init.make_tracing_request();
    set_context(req.get().get_context()?, &remote_thread, &local_thread);
    let response = req.send().promise.await?;
    let tracing = response.get()?.get_result()?;

    let interval = Rc::new(RefCell::new(Counters::default()));
    let mut req = tracing.trace_net_messages_request();
    {
        let mut p = req.get();
        set_context(p.reborrow().get_context()?, &remote_thread, &local_thread);
        let mut o = p.reborrow().init_options();
        o.set_inbound(true);
        o.set_outbound(true);
        o.set_max_payload_bytes(args.payload);
        o.set_max_queue_events(args.queue);
        o.set_max_batch_events(args.batch);
        o.set_max_batch_wait_us(args.batchwait);
        p.set_callback(capnp_rpc::new_client(TraceImpl {
            interval: interval.clone(),
        }));
    }
    let response = req.send().promise.await?;
    let handler = response.get()?.get_result()?;

    println!("{{\"event\":\"ready\",\"pid\":{}}}", process::id());
    let start = Instant::now();
    let mut total = Counters::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.tick().await; // first tick completes immediately
    let deadline = if args.duration > 0.0 {
        Some(start + Duration::from_secs_f64(args.duration))
    } else {
        None
    };
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut disconnected = false;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let c = std::mem::take(&mut *interval.borrow_mut());
                total.add(&c);
                if !args.quiet {
                    let elapsed = start.elapsed().as_secs_f64();
                    if args.json {
                        println!("{{{},\"event\":\"stats\",\"elapsed_s\":{}}}", c.to_json(1.0), elapsed);
                    } else {
                        let mean = if c.events > 0 { c.lat_sum_us as f64 / c.events as f64 } else { 0.0 };
                        println!(
                            "t={:.0}s events={} (in={} out={}) bytes={} dropped={} batches={} lat_mean_us={:.1} lat_max_us={}",
                            elapsed, c.events, c.events_in, c.events_out, c.bytes, c.dropped, c.batches, mean, c.lat_max_us
                        );
                    }
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    break;
                }
            }
            _ = &mut ctrl_c => break,
            _ = sigterm.recv() => break,
        }
        if rpc_task.is_finished() {
            disconnected = true;
            break;
        }
    }
    let duration = start.elapsed().as_secs_f64();
    total.add(&std::mem::take(&mut *interval.borrow_mut()));

    if !disconnected {
        // Unsubscribe; ignore errors if the node is already gone.
        let mut req = handler.destroy_request();
        set_context(req.get().get_context()?, &remote_thread, &local_thread);
        let _ = tokio::time::timeout(Duration::from_secs(10), req.send().promise).await;
    }

    let summary = format!(
        "{{{},\"mode\":\"ipc\",\"engine\":\"rust\",\"event\":\"summary\",\"payload_bytes\":{},\"queue_events\":{},\"batch_events\":{},\"batch_wait_us\":{}}}",
        total.to_json(duration),
        args.payload,
        args.queue,
        args.batch,
        args.batchwait
    );
    match &args.out {
        Some(path) => fs::write(path, format!("{summary}\n"))?,
        None => println!("{summary}"),
    }
    if disconnected {
        eprintln!("Error: lost connection to bitcoin-node");
        process::exit(1);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(tokio::task::LocalSet::new().run_until(run(args)))
}
