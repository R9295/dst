mod det_quic;
mod ffi;
mod mock_validator;

use {
    crate::{
        ffi::{DetSnapshot, DetVm, StopReason},
        mock_validator::{ClusterSetup, MOCK_IP, MockStats, MockValidator, TEST_IP},
    },
    solana_clock::Slot,
    solana_sha256_hasher::hash,
    solana_signer::Signer,
    std::{
        collections::BTreeSet,
        net::{IpAddr, Ipv4Addr},
        os::raw::{c_int, c_void},
        path::{Path, PathBuf},
        time::Instant,
    },
};

struct OutputWatcher {
    line_buf: String,
    finalized_slots: BTreeSet<Slot>,
    rooted_slots: BTreeSet<Slot>,
    highest_rooted: Slot,
    target_roots: Slot,
    echo_logs: bool,
    all_output: Vec<u8>,
}

impl OutputWatcher {
    fn new(target_roots: Slot, echo_logs: bool) -> Self {
        Self {
            line_buf: String::new(),
            finalized_slots: BTreeSet::new(),
            rooted_slots: BTreeSet::new(),
            highest_rooted: 0,
            target_roots,
            echo_logs,
            all_output: Vec::new(),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        self.all_output.extend_from_slice(data);
        if self.echo_logs {
            use std::io::Write;
            let _ = std::io::stderr().write_all(data);
        }
        let s = String::from_utf8_lossy(data);
        self.line_buf.push_str(&s);
        while let Some(nl) = self.line_buf.find('\n') {
            let line = self.line_buf[..nl].to_string();
            self.line_buf.drain(..=nl);
            self.parse_line(&line);
        }
    }

    fn parse_line(&mut self, line: &str) {
        if let Some(pos) = line.find("new root ") {
            let rest = &line[pos + "new root ".len()..];
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(slot) = num_str.parse::<Slot>() {
                self.rooted_slots.insert(slot);
                if slot > self.highest_rooted {
                    self.highest_rooted = slot;
                }
                eprintln!("[harness] >>> Test validator ROOTED slot {slot} ({}/{}) <<<",
                    self.rooted_slots.len(), self.target_roots);
            }
        } else if let Some(pos) = line.find("Finalized Block { slot: ") {
            let rest = &line[pos + "Finalized Block { slot: ".len()..];
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(slot) = num_str.parse::<Slot>() {
                self.finalized_slots.insert(slot);
                eprintln!("[harness] >>> Test validator FINALIZED slot {slot} <<<");
            }
        } else if line.contains("Validator initialized")
            || line.contains("bank frozen:")
            || line.contains("BankHashMismatch")
            || line.contains("dead slot")
            || line.contains("ERROR")
        {
            if !self.echo_logs {
                eprintln!("[guest] {line}");
            }
        }
    }
}

extern "C" fn output_trampoline(ctx: *mut c_void, _fd: c_int, data: *const u8, len: usize) {
    if ctx.is_null() || data.is_null() || len == 0 {
        return;
    }
    let watcher = unsafe { &mut *(ctx as *mut OutputWatcher) };
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    watcher.feed(slice);
}

#[derive(Debug, Clone)]
struct RunSummary {
    highest_rooted: Slot,
    rooted_slots: Vec<Slot>,
    finalized_slots: Vec<Slot>,
    vmono_ns: u64,
    syscalls: u64,
    preempts: u64,
    pmu_overshoots: u64,
    state_hash: u64,
    output_sha256: String,
    output_len: usize,
    mock_stats: MockStats,
    wall_secs: f64,
}

fn boot_and_snapshot_validator(
    setup: &ClusterSetup,
    validator_bin: &Path,
    snap_path: &Path,
    ram_mb: usize,
    seed: u64,
    quantum: u64,
    echo_logs: bool,
) -> Result<(DetVm, DetSnapshot), String> {
    eprintln!("=== Stage 1: Booting unmodified agave-validator inside DetHV to startup snapshot ===");
    let t0 = Instant::now();

    let mut vm = DetVm::new(ram_mb, seed, quantum, true)?;
    vm.set_peer_ip(TEST_IP, MOCK_IP);

    // Import generated genesis ledger & keypairs into DetHV's isolated in-memory VFS
    vm.import_host_dir(&setup.ledger_dir, "/tmp/ledger")?;
    let id_bytes = std::fs::read(&setup.test_identity_path).map_err(|e| e.to_string())?;
    let vote_bytes = std::fs::read(&setup.test_vote_path).map_err(|e| e.to_string())?;
    vm.set_vfile("/tmp/test-identity.json", &id_bytes)?;
    vm.set_vfile("/tmp/test-vote.json", &vote_bytes)?;

    let args = vec![
        validator_bin.to_string_lossy().into_owned(),
        "--ledger".into(),
        "/tmp/ledger".into(),
        "--identity".into(),
        "/tmp/test-identity.json".into(),
        "--vote-account".into(),
        "/tmp/test-vote.json".into(),
        "--bind-address".into(),
        TEST_IP.to_string(),
        "--gossip-port".into(),
        "8001".into(),
        "--dynamic-port-range".into(),
        "8000-8050".into(),
        "--entrypoint".into(),
        format!("{MOCK_IP}:8001"),
        "--expected-genesis-hash".into(),
        setup.genesis_hash.to_string(),
        "--expected-shred-version".into(),
        setup.shred_version.to_string(),
        "--no-xdp".into(),
        "--allow-private-addr".into(),
        "--no-port-check".into(),
        "--no-os-network-limits-test".into(),
        "--no-os-memory-stats-reporting".into(),
        "--no-os-network-stats-reporting".into(),
        "--no-os-cpu-stats-reporting".into(),
        "--no-os-disk-stats-reporting".into(),
        "--no-genesis-fetch".into(),
        "--no-snapshot-fetch".into(),
        "--no-snapshots".into(),
        "--no-accounts-db-snapshots-direct-io".into(),
        "--do-not-require-vote-history".into(),
        "--init-complete-file".into(),
        "/tmp/init_complete".into(),
        "--log".into(),
        "-".into(),
    ];

    let envs = vec![
        "PATH=/usr/local/bin:/usr/bin:/bin".into(),
        "HOME=/root".into(),
        "USER=root".into(),
        "TMPDIR=/tmp".into(),
        "LANG=C".into(),
        "LC_ALL=C".into(),
        "TZ=UTC".into(),
        "RUST_LOG=info,solana_metrics=warn".into(),
    ];

    vm.load_elf(validator_bin, &args, &envs)?;
    vm.set_snapshot_on_open("init_complete");

    let mut watcher = Box::new(OutputWatcher::new(8, echo_logs));
    let wptr: *mut OutputWatcher = &mut *watcher;
    vm.set_output_cb(Some(output_trampoline), wptr as *mut c_void);

    let boot_res = vm.run();
    vm.set_output_cb(None, std::ptr::null_mut());

    if boot_res.stop_reason() != StopReason::Snapshot {
        return Err(format!(
            "agave-validator stopped with {:?} (exit={}, sig={}, rip=0x{:x}, cr2=0x{:x}) before init_complete!\nLast stderr:\n{}",
            boot_res.stop_reason(),
            boot_res.exit_code,
            boot_res.signal,
            boot_res.fault_rip,
            boot_res.fault_addr,
            String::from_utf8_lossy(&watcher.all_output[watcher.all_output.len().saturating_sub(4096)..]),
        ));
    }

    let snap = vm.snapshot_take()?;
    snap.save_file(snap_path)?;
    let ports = vm.bound_udp_ports();
    eprintln!(
        "[harness] Startup snapshot captured & saved to {} in {:.2}s (vmono={:.3}s, syscalls={}, preempts={}, overshoots={}, bound_udp_ports={:?})",
        snap_path.display(),
        t0.elapsed().as_secs_f64(),
        vm.vmono_ns() as f64 / 1e9,
        boot_res.syscalls,
        boot_res.preempts,
        boot_res.pmu_overshoots,
        ports
    );

    Ok((vm, snap))
}

fn run_mock_until_finalized(
    vm: &mut DetVm,
    snap: &DetSnapshot,
    setup: &ClusterSetup,
    target_slots: Slot,
    max_virtual_secs: u64,
    echo_logs: bool,
) -> Result<RunSummary, String> {
    let t0 = Instant::now();
    vm.snapshot_restore(snap)?;
    vm.set_peer_ip(TEST_IP, MOCK_IP);

    let mut watcher = Box::new(OutputWatcher::new(target_slots, echo_logs));
    let wptr: *mut OutputWatcher = &mut *watcher;
    vm.set_output_cb(Some(output_trampoline), wptr as *mut c_void);

    // Build up to target_slots (slots 1..=8, all led by Mock Validator!)
    let mut mock = MockValidator::new(setup, target_slots);

    let start_vmono = vm.vmono_ns();
    let max_vmono = start_vmono + max_virtual_secs * 1_000_000_000;
    let step_ns: u64 = 10_000_000; // 10 ms deterministic virtual time steps

    let mut last_res = Default::default();
    let mut step_count = 0u64;

    while watcher.highest_rooted < target_slots {
        let now_ns = vm.vmono_ns();
        let vtime_ns = vm.vtime_ns();
        if now_ns >= max_vmono {
            vm.set_output_cb(None, std::ptr::null_mut());
            return Err(format!(
                "Timed out after {max_virtual_secs}s virtual time (highest_rooted={}, finalized={:?}, mock_stats={:?})",
                watcher.highest_rooted, watcher.finalized_slots, mock.stats
            ));
        }

        // Advance Mock Validator timers, block building, certs, QUIC
        mock.tick(now_ns, vtime_ns, watcher.highest_rooted);

        // Flush all outbound UDP packets from Mock Validator into DetHV guest!
        for pkt in mock.pending_tx.drain(..) {
            let IpAddr::V4(dst_v4) = pkt.dst.ip() else { continue };
            let _ = vm.inject_udp(MOCK_IP, pkt.local_port, dst_v4, pkt.dst.port(), &pkt.payload);
        }

        // Step DetHV deterministically (stops immediately on any TX packet to MOCK_IP or after 10ms)
        last_res = vm.run_step(now_ns + step_ns, true);
        step_count += 1;

        // Drain all guest TX packets destined for Mock Validator
        while let Some(tx) = vm.pop_tx() {
            let src_ip = Ipv4Addr::from(tx.src_ip);
            let payload = &tx.data[..tx.len as usize];
            mock.on_guest_udp(src_ip, tx.src_port, tx.dst_port, payload, tx.vmono_ns, vm.vtime_ns());
        }

        // Flush immediate responses (Gossip Pong/Push, Repair shreds, QUIC handshake ACKs!)
        for pkt in mock.pending_tx.drain(..) {
            let IpAddr::V4(dst_v4) = pkt.dst.ip() else { continue };
            let _ = vm.inject_udp(MOCK_IP, pkt.local_port, dst_v4, pkt.dst.port(), &pkt.payload);
        }

        match last_res.stop_reason() {
            StopReason::Step | StopReason::NetTx => {}
            other => {
                vm.set_output_cb(None, std::ptr::null_mut());
                return Err(format!(
                    "Guest stopped unexpectedly with {:?} (exit={}, sig={}, rip=0x{:x}, cr2=0x{:x}) at step {}",
                    other, last_res.exit_code, last_res.signal, last_res.fault_rip, last_res.fault_addr, step_count
                ));
            }
        }
    }

    vm.set_output_cb(None, std::ptr::null_mut());
    let output_sha256 = hash(&watcher.all_output).to_string();

    Ok(RunSummary {
        highest_rooted: watcher.highest_rooted,
        rooted_slots: watcher.rooted_slots.iter().copied().collect(),
        finalized_slots: watcher.finalized_slots.iter().copied().collect(),
        vmono_ns: vm.vmono_ns() - start_vmono,
        syscalls: last_res.syscalls,
        preempts: last_res.preempts,
        pmu_overshoots: last_res.pmu_overshoots,
        state_hash: last_res.state_hash,
        output_sha256,
        output_len: watcher.all_output.len(),
        mock_stats: mock.stats,
        wall_secs: t0.elapsed().as_secs_f64(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut verify_runs = 2usize;
    let mut target_slots: Slot = 8;
    let mut echo_logs = false;
    let mut load_snap_only: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--verify" if i + 1 < args.len() => {
                i += 1;
                verify_runs = args[i].parse()?;
            }
            "--slots" if i + 1 < args.len() => {
                i += 1;
                target_slots = args[i].parse()?;
            }
            "--echo-logs" => echo_logs = true,
            "--load-snap" if i + 1 < args.len() => {
                i += 1;
                load_snap_only = Some(PathBuf::from(&args[i]));
            }
            other => {
                eprintln!("Unknown option: {other}");
                eprintln!("Usage: validator-harness [--verify N] [--slots N] [--load-snap file.dhvs] [--echo-logs]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let validator_bin = repo_root.join("agave/target/release/agave-validator");
    let genesis_bin = repo_root.join("agave/target/release/solana-genesis");
    let work_dir = repo_root.join("build/validator-test-cluster");
    let snap_path = repo_root.join("build/agave_startup.dhvs");

    if !validator_bin.exists() || !genesis_bin.exists() {
        return Err(format!(
            "Missing Agave release binaries! Expected:\n  {}\n  {}",
            validator_bin.display(),
            genesis_bin.display()
        )
        .into());
    }

    let setup = ClusterSetup::create(&work_dir, &genesis_bin)?;
    eprintln!("=== Deterministic 2-Validator Genesis Configured ===");
    eprintln!(
        "  Genesis hash  : {} (shred_version={})",
        setup.genesis_hash, setup.shred_version
    );
    eprintln!(
        "  Mock validator: id={} vote={} stake={} SOL (60%, rank={}, leader for ALL slots 0..=11)",
        setup.mock_identity.pubkey(),
        setup.mock_vote.pubkey(),
        setup.mock_active_stake / 1_000_000_000,
        setup.mock_rank
    );
    eprintln!(
        "  Test validator: id={} vote={} stake={} SOL (40%)",
        setup.test_identity.pubkey(),
        setup.test_vote.pubkey(),
        setup.test_active_stake / 1_000_000_000
    );

    let ram_mb = 4096;
    let seed = 0xDE7E4157_00000001u64;
    let quantum = 200_000u64;

    let (mut vm, snap) = if let Some(path) = load_snap_only {
        eprintln!("=== Loading existing startup snapshot {} ===", path.display());
        let vm = DetVm::new(ram_mb, seed, quantum, true)?;
        let snap = DetSnapshot::load_file(&path)?;
        (vm, snap)
    } else {
        boot_and_snapshot_validator(&setup, &validator_bin, &snap_path, ram_mb, seed, quantum, echo_logs)?
    };

    eprintln!(
        "\n=== Stage 2: Serving from startup snapshot until {target_slots} slots finalized ({verify_runs} run(s)) ==="
    );

    let mut summaries = Vec::new();
    for run_idx in 0..verify_runs {
        eprintln!("\n--- Deterministic Snapshot Run {}/{} ---", run_idx + 1, verify_runs);
        // For run >= 1, test reloading the saved .dhvs disk snapshot in a brand new DetVm!
        let summary = if run_idx == 0 {
            run_mock_until_finalized(&mut vm, &snap, &setup, target_slots, 30, echo_logs)?
        } else {
            let mut fresh_vm = DetVm::new(ram_mb, seed, quantum, true)?;
            let disk_snap = DetSnapshot::load_file(&snap_path)?;
            run_mock_until_finalized(&mut fresh_vm, &disk_snap, &setup, target_slots, 30, echo_logs)?
        };
        eprintln!(
            "[run {}] PASS: rooted={:?} finalized={:?} vtime={:.3}s wall={:.2}s\n\
             \tsyscalls={} preempts={} pmu_overshoots={} state_hash=0x{:016x}\n\
             \toutput_len={} output_sha256={}\n\
             \tmock_stats={:?}",
            run_idx + 1,
            summary.rooted_slots,
            summary.finalized_slots,
            summary.vmono_ns as f64 / 1e9,
            summary.wall_secs,
            summary.syscalls,
            summary.preempts,
            summary.pmu_overshoots,
            summary.state_hash,
            summary.output_len,
            summary.output_sha256,
            summary.mock_stats
        );
        summaries.push(summary);
    }

    // Assert Turbine, Repair, Certificates, and 8 finalized slots!
    let s0 = &summaries[0];
    assert!(s0.highest_rooted >= target_slots, "did not finalize {target_slots} slots");
    assert!(s0.mock_stats.turbine_shreds_sent > 0, "expected Turbine shreds sent");
    assert!(s0.mock_stats.repair_tx > 0, "expected Repair responses served");
    assert!(s0.mock_stats.certs_sent >= target_slots * 2, "expected Notar+Finalize certs sent");

    // Assert 100% BIT-FOR-BIT DETERMINISM across all runs!
    for (idx, s) in summaries.iter().enumerate().skip(1) {
        if s.state_hash != s0.state_hash
            || s.output_sha256 != s0.output_sha256
            || s.syscalls != s0.syscalls
            || s.preempts != s0.preempts
            || s.rooted_slots != s0.rooted_slots
        {
            return Err(format!(
                "NON-DETERMINISM DETECTED on run {}!\n  run1: {:?}\n  run{}: {:?}",
                idx + 1,
                s0,
                idx + 1,
                s
            )
            .into());
        }
    }

    eprintln!(
        "\n================================================================================\n\
         SUCCESS: {}/{} snapshot-reloaded agave-validator runs finalized {} slots\n\
         100% BIT-FOR-BIT IDENTICAL!\n\
         - state_hash    : 0x{:016x}\n\
         - output_sha256 : {} ({} bytes)\n\
         - turbine_sent  : {} shreds | repair_served : {} pkts | certs_sent : {}\n\
         ================================================================================",
        verify_runs,
        verify_runs,
        target_slots,
        s0.state_hash,
        s0.output_sha256,
        s0.output_len,
        s0.mock_stats.turbine_shreds_sent,
        s0.mock_stats.repair_tx,
        s0.mock_stats.certs_sent,
    );

    Ok(())
}
