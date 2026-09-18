// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! libbpf-rs receiver for the `net:inbound_message` and `net:outbound_message`
//! USDT tracepoints, using a BPF ring buffer. Same command line and JSON
//! summary schema as the BCC/bpftrace receivers in `contrib/tracing/bench/`,
//! so `run_bench.py --engine libbpf` can drive it.
//!
//! Needs root. Delivery latency is `CLOCK_MONOTONIC` now minus
//! `bpf_ktime_get_ns()` at the tracepoint.

use std::cell::RefCell;
use std::fs;
use std::io::Write;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

mod net_msgs {
    include!(concat!(env!("OUT_DIR"), "/net_msgs.skel.rs"));
}
use net_msgs::*;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const MAX_MSG_TYPE_LENGTH: usize = 20;
const MAX_PAYLOAD: usize = 64;

/// Must match `struct msg_event` in net_msgs.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
struct MsgEvent {
    ts_ns: u64,
    peer_id: u64,
    msg_size: u64,
    inbound: u64,
    msg_type: [u8; MAX_MSG_TYPE_LENGTH],
    payload: [u8; MAX_PAYLOAD],
}
unsafe impl Plain for MsgEvent {}

#[derive(Default, Clone, Copy)]
struct Counters {
    events: u64,
    events_in: u64,
    events_out: u64,
    ping_in: u64,
    pong_out: u64,
    bytes: u64,
    dropped: u64,
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
            "\"events\":{},\"events_in\":{},\"events_out\":{},\"ping_in\":{},\"pong_out\":{},\"bytes\":{},\"dropped\":{},\"batches\":0,\"duration_s\":{},\"events_per_s\":{},\"latency_us\":{{\"mean\":{},\"max\":{}}}",
            self.events, self.events_in, self.events_out, self.ping_in, self.pong_out, self.bytes, self.dropped,
            seconds, rate, mean, self.lat_max_us
        )
    }
}

struct Args {
    pid: i32,
    payload: u32,
    page_cnt: u32,
    duration: f64,
    ready_file: Option<PathBuf>,
    stop_file: Option<PathBuf>,
    out: Option<PathBuf>,
    json: bool,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: net-msgs-libbpf --pid <pid> [--payload <bytes, max {MAX_PAYLOAD}>] [--page-cnt <4KiB pages of ring buffer>] \
         [--duration <s>] [--ready-file <f>] [--stop-file <f>] [--out <f>] [--json] [--quiet]"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        pid: 0,
        payload: 0,
        page_cnt: 1024,
        duration: 0.0,
        ready_file: None,
        stop_file: None,
        out: None,
        json: false,
        quiet: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--pid" => args.pid = value().parse().unwrap_or_else(|_| usage()),
            "--payload" => args.payload = value().parse().unwrap_or_else(|_| usage()),
            "--page-cnt" => args.page_cnt = value().parse().unwrap_or_else(|_| usage()),
            "--duration" => args.duration = value().parse().unwrap_or_else(|_| usage()),
            "--ready-file" => args.ready_file = Some(PathBuf::from(value())),
            "--stop-file" => args.stop_file = Some(PathBuf::from(value())),
            "--out" => args.out = Some(PathBuf::from(value())),
            "--json" => args.json = true,
            "--quiet" => args.quiet = true,
            _ => usage(),
        }
    }
    if args.pid <= 0 {
        usage();
    }
    if args.payload as usize > MAX_PAYLOAD {
        eprintln!("--payload is capped at {MAX_PAYLOAD} bytes");
        args.payload = MAX_PAYLOAD as u32;
    }
    args
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain libc call with a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let exe = fs::read_link(format!("/proc/{}/exe", args.pid))?;

    // SAFETY: the handlers only set an atomic flag.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }

    let skel_builder = NetMsgsSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .expect("rodata is not memory mapped")
        .max_payload = args.payload;
    // Ring buffer size must be a power-of-two multiple of the page size.
    let mut ring_bytes: u32 = args.page_cnt.max(1).saturating_mul(4096);
    ring_bytes = ring_bytes.next_power_of_two();
    open_skel.maps.events.set_max_entries(ring_bytes)?;
    let skel = open_skel.load()?;

    let interval = RefCell::new(Counters::default());
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events, |data: &[u8]| -> i32 {
        let now_ns = monotonic_ns();
        let Ok(e) = plain::from_bytes::<MsgEvent>(data) else {
            return 0;
        };
        let lat_us = now_ns.saturating_sub(e.ts_ns) / 1000;
        let mut c = interval.borrow_mut();
        c.events += 1;
        c.bytes += e.msg_size;
        c.lat_sum_us += lat_us;
        c.lat_max_us = c.lat_max_us.max(lat_us);
        let msg_type = &e.msg_type[..e
            .msg_type
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_MSG_TYPE_LENGTH)];
        if e.inbound != 0 {
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
        0
    })?;
    let ring = builder.build()?;

    let _link_in =
        skel.progs
            .inbound_message
            .attach_usdt(args.pid, &exe, "net", "inbound_message")?;
    let _link_out =
        skel.progs
            .outbound_message
            .attach_usdt(args.pid, &exe, "net", "outbound_message")?;

    if let Some(path) = &args.ready_file {
        fs::write(path, format!("{}\n", process::id()))?;
    }
    println!("{{\"event\":\"ready\",\"pid\":{}}}", process::id());

    let start = Instant::now();
    let mut next_tick = start + Duration::from_secs(1);
    let mut total = Counters::default();
    while !STOP.load(Ordering::SeqCst) {
        ring.poll(Duration::from_millis(50))?;
        let now = Instant::now();
        if args.duration > 0.0 && now.duration_since(start).as_secs_f64() >= args.duration {
            break;
        }
        if args.stop_file.as_ref().is_some_and(|p| p.exists()) {
            break;
        }
        if now >= next_tick {
            next_tick += Duration::from_secs(1);
            let c = std::mem::take(&mut *interval.borrow_mut());
            total.add(&c);
            if !args.quiet {
                let elapsed = now.duration_since(start).as_secs_f64();
                if args.json {
                    println!(
                        "{{{},\"event\":\"stats\",\"elapsed_s\":{}}}",
                        c.to_json(1.0),
                        elapsed
                    );
                } else {
                    let mean = if c.events > 0 {
                        c.lat_sum_us as f64 / c.events as f64
                    } else {
                        0.0
                    };
                    println!(
                        "t={:.0}s events={} (in={} out={}) bytes={} lat_mean_us={:.1} lat_max_us={}",
                        elapsed, c.events, c.events_in, c.events_out, c.bytes, mean, c.lat_max_us
                    );
                }
                let _ = std::io::stdout().flush();
            }
        }
    }
    // Drain what is left, then read the kernel-side drop counter.
    ring.poll(Duration::from_millis(200))?;
    let c = std::mem::take(&mut *interval.borrow_mut());
    total.add(&c);
    let duration = start.elapsed().as_secs_f64();
    total.dropped = skel
        .maps
        .bss_data
        .as_deref()
        .expect("bss is not memory mapped")
        .dropped;

    let summary = format!(
        "{{{},\"mode\":\"ebpf\",\"engine\":\"libbpf-rs\",\"event\":\"summary\",\"payload_bytes\":{},\"page_cnt\":{},\"ringbuf_bytes\":{}}}",
        total.to_json(duration),
        args.payload,
        args.page_cnt,
        ring_bytes
    );
    match &args.out {
        Some(path) => fs::write(path, format!("{summary}\n"))?,
        None => println!("{summary}"),
    }
    Ok(())
}
