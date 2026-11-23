#![allow(dead_code)]

use std::{
    ffi::{CStr, CString},
    net::Ipv4Addr,
    os::raw::{c_char, c_int, c_void},
    path::Path,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StopReason {
    None = 0,
    Exited = 1,
    CrashSegv = 2,
    CrashIll = 3,
    CrashFpe = 4,
    CrashAbrt = 5,
    CrashBus = 6,
    CrashTrap = 7,
    Snapshot = 8,
    Step = 9,
    NetTx = 10,
    Timeout = 11,
    Deadlock = 12,
    Error = 13,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DethvConfig {
    pub ram_size: usize,
    pub seed: u64,
    pub start_time_ns: u64,
    pub preempt_quantum: u64,
    pub max_syscalls: u64,
    pub max_preempts: u64,
    pub trace_syscalls: bool,
    pub capture_output: bool,
    pub enable_pmu: bool,
    pub patch_rdrand: bool,
    pub allow_host_ro: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DethvRunResult {
    pub reason: u32,
    pub exit_code: c_int,
    pub signal: c_int,
    pub fault_rip: u64,
    pub fault_addr: u64,
    pub fault_errcode: u64,
    pub syscalls: u64,
    pub preempts: u64,
    pub rdtsc_traps: u64,
    pub rdrand_traps: u64,
    pub getrandom_calls: u64,
    pub total_threads: u64,
    pub pmu_overshoots: u64,
    pub dirty_pages: u64,
    pub state_hash: u64,
    pub stdout_hash: u64,
    pub stdout_len: usize,
    pub stderr_len: usize,
}

impl DethvRunResult {
    pub fn stop_reason(&self) -> StopReason {
        match self.reason {
            0 => StopReason::None,
            1 => StopReason::Exited,
            2 => StopReason::CrashSegv,
            3 => StopReason::CrashIll,
            4 => StopReason::CrashFpe,
            5 => StopReason::CrashAbrt,
            6 => StopReason::CrashBus,
            7 => StopReason::CrashTrap,
            8 => StopReason::Snapshot,
            9 => StopReason::Step,
            10 => StopReason::NetTx,
            11 => StopReason::Timeout,
            12 => StopReason::Deadlock,
            _ => StopReason::Error,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct DethvUdpPkt {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub vmono_ns: u64,
    pub len: u32,
    pub data: [u8; 1600],
}

impl Default for DethvUdpPkt {
    fn default() -> Self {
        Self {
            src_ip: 0,
            src_port: 0,
            dst_ip: 0,
            dst_port: 0,
            vmono_ns: 0,
            len: 0,
            data: [0u8; 1600],
        }
    }
}

pub enum DethvVmRaw {}
pub enum DethvSnapshotRaw {}

pub type OutputCb = extern "C" fn(ctx: *mut c_void, fd: c_int, data: *const u8, len: usize);

unsafe extern "C" {
    pub fn dethv_config_default(cfg: *mut DethvConfig);
    pub fn dethv_create(cfg: *const DethvConfig) -> *mut DethvVmRaw;
    pub fn dethv_destroy(vm: *mut DethvVmRaw);
    pub fn dethv_load_elf(
        vm: *mut DethvVmRaw,
        path: *const c_char,
        argc: c_int,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    pub fn dethv_set_snapshot_on_open(vm: *mut DethvVmRaw, path_substr: *const c_char);
    pub fn dethv_set_vfile(
        vm: *mut DethvVmRaw,
        path: *const c_char,
        data: *const c_void,
        len: usize,
    ) -> c_int;
    pub fn dethv_set_vdir(vm: *mut DethvVmRaw, path: *const c_char) -> c_int;
    pub fn dethv_import_host_dir(
        vm: *mut DethvVmRaw,
        host_dir: *const c_char,
        guest_dir: *const c_char,
    ) -> c_int;
    pub fn dethv_get_stdout(vm: *const DethvVmRaw, len_out: *mut usize) -> *const u8;
    pub fn dethv_get_stderr(vm: *const DethvVmRaw, len_out: *mut usize) -> *const u8;
    pub fn dethv_set_output_cb(vm: *mut DethvVmRaw, cb: Option<OutputCb>, ctx: *mut c_void);
    pub fn dethv_get_vmono_ns(vm: *const DethvVmRaw) -> u64;
    pub fn dethv_get_vtime_ns(vm: *const DethvVmRaw) -> u64;
    pub fn dethv_net_set_peer_ip(vm: *mut DethvVmRaw, guest_ip: u32, peer_ip: u32);
    pub fn dethv_net_inject_udp(
        vm: *mut DethvVmRaw,
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        data: *const c_void,
        len: usize,
    ) -> c_int;
    pub fn dethv_net_pop_tx(vm: *mut DethvVmRaw, out: *mut DethvUdpPkt) -> c_int;
    pub fn dethv_net_get_bound_udp_ports(
        vm: *const DethvVmRaw,
        ports_out: *mut u16,
        max_ports: usize,
    ) -> usize;
    pub fn dethv_run(vm: *mut DethvVmRaw, res: *mut DethvRunResult) -> c_int;
    pub fn dethv_run_step(
        vm: *mut DethvVmRaw,
        until_vmono_ns: u64,
        stop_on_tx: bool,
        res: *mut DethvRunResult,
    ) -> c_int;
    pub fn dethv_snapshot_take(vm: *mut DethvVmRaw) -> *mut DethvSnapshotRaw;
    pub fn dethv_snapshot_restore(vm: *mut DethvVmRaw, snap: *const DethvSnapshotRaw) -> c_int;
    pub fn dethv_snapshot_free(snap: *mut DethvSnapshotRaw);
    pub fn dethv_snapshot_save_file(snap: *const DethvSnapshotRaw, path: *const c_char) -> c_int;
    pub fn dethv_snapshot_load_file(path: *const c_char) -> *mut DethvSnapshotRaw;
    pub fn dethv_stop_reason_str(reason: u32) -> *const c_char;
}

pub struct DetSnapshot {
    raw: *mut DethvSnapshotRaw,
}

impl DetSnapshot {
    pub fn load_file(path: &Path) -> Result<Self, String> {
        let cpath = CString::new(path.to_str().ok_or("invalid path")?).unwrap();
        let raw = unsafe { dethv_snapshot_load_file(cpath.as_ptr()) };
        if raw.is_null() {
            Err(format!("failed to load snapshot from {}", path.display()))
        } else {
            Ok(Self { raw })
        }
    }

    pub fn save_file(&self, path: &Path) -> Result<(), String> {
        let cpath = CString::new(path.to_str().ok_or("invalid path")?).unwrap();
        let rc = unsafe { dethv_snapshot_save_file(self.raw, cpath.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("failed to save snapshot to {}", path.display()))
        }
    }
}

impl Drop for DetSnapshot {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { dethv_snapshot_free(self.raw) };
        }
    }
}

pub struct DetVm {
    raw: *mut DethvVmRaw,
}

impl DetVm {
    pub fn new(ram_mb: usize, seed: u64, preempt_quantum: u64, capture_output: bool) -> Result<Self, String> {
        let mut cfg = std::mem::MaybeUninit::<DethvConfig>::uninit();
        unsafe { dethv_config_default(cfg.as_mut_ptr()) };
        let mut cfg = unsafe { cfg.assume_init() };
        cfg.ram_size = ram_mb * 1024 * 1024;
        cfg.seed = seed;
        cfg.preempt_quantum = preempt_quantum;
        cfg.capture_output = capture_output;

        let raw = unsafe { dethv_create(&cfg) };
        if raw.is_null() {
            Err("dethv_create failed".to_string())
        } else {
            Ok(Self { raw })
        }
    }

    pub fn load_elf(&mut self, path: &Path, args: &[String], envs: &[String]) -> Result<(), String> {
        let cpath = CString::new(path.to_str().ok_or("invalid elf path")?).unwrap();
        let cargs: Vec<CString> = args.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
        let mut arg_ptrs: Vec<*const c_char> = cargs.iter().map(|s| s.as_ptr()).collect();
        arg_ptrs.push(std::ptr::null());

        let cenvs: Vec<CString> = envs.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
        let mut env_ptrs: Vec<*const c_char> = cenvs.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());

        let rc = unsafe {
            dethv_load_elf(
                self.raw,
                cpath.as_ptr(),
                cargs.len() as c_int,
                arg_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("dethv_load_elf failed for {}", path.display()))
        }
    }

    pub fn set_snapshot_on_open(&mut self, substr: &str) {
        let cs = CString::new(substr).unwrap();
        unsafe { dethv_set_snapshot_on_open(self.raw, cs.as_ptr()) };
    }

    pub fn set_vfile(&mut self, guest_path: &str, data: &[u8]) -> Result<(), String> {
        let cs = CString::new(guest_path).unwrap();
        let rc = unsafe { dethv_set_vfile(self.raw, cs.as_ptr(), data.as_ptr() as *const c_void, data.len()) };
        if rc == 0 { Ok(()) } else { Err(format!("dethv_set_vfile({guest_path}) failed")) }
    }

    pub fn import_host_dir(&mut self, host_dir: &Path, guest_dir: &str) -> Result<(), String> {
        let ch = CString::new(host_dir.to_str().ok_or("invalid host_dir")?).unwrap();
        let cg = CString::new(guest_dir).unwrap();
        let rc = unsafe { dethv_import_host_dir(self.raw, ch.as_ptr(), cg.as_ptr()) };
        if rc == 0 { Ok(()) } else { Err(format!("dethv_import_host_dir failed")) }
    }

    pub fn set_peer_ip(&mut self, guest_ip: Ipv4Addr, peer_ip: Ipv4Addr) {
        unsafe { dethv_net_set_peer_ip(self.raw, u32::from(guest_ip), u32::from(peer_ip)) };
    }

    pub fn inject_udp(
        &mut self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        let rc = unsafe {
            dethv_net_inject_udp(
                self.raw,
                u32::from(src_ip),
                src_port,
                u32::from(dst_ip),
                dst_port,
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        rc == 0
    }

    pub fn pop_tx(&mut self) -> Option<DethvUdpPkt> {
        let mut pkt = DethvUdpPkt::default();
        let got = unsafe { dethv_net_pop_tx(self.raw, &mut pkt) };
        if got > 0 { Some(pkt) } else { None }
    }

    pub fn bound_udp_ports(&self) -> Vec<u16> {
        let mut ports = vec![0u16; 256];
        let n = unsafe { dethv_net_get_bound_udp_ports(self.raw, ports.as_mut_ptr(), ports.len()) };
        ports.truncate(n);
        ports
    }

    pub fn vmono_ns(&self) -> u64 {
        unsafe { dethv_get_vmono_ns(self.raw) }
    }

    pub fn vtime_ns(&self) -> u64 {
        unsafe { dethv_get_vtime_ns(self.raw) }
    }

    pub fn set_output_cb(&mut self, cb: Option<OutputCb>, ctx: *mut c_void) {
        unsafe { dethv_set_output_cb(self.raw, cb, ctx) };
    }

    pub fn run(&mut self) -> DethvRunResult {
        let mut res = DethvRunResult::default();
        unsafe { dethv_run(self.raw, &mut res) };
        res
    }

    pub fn run_step(&mut self, until_vmono_ns: u64, stop_on_tx: bool) -> DethvRunResult {
        let mut res = DethvRunResult::default();
        unsafe { dethv_run_step(self.raw, until_vmono_ns, stop_on_tx, &mut res) };
        res
    }

    pub fn snapshot_take(&mut self) -> Result<DetSnapshot, String> {
        let raw = unsafe { dethv_snapshot_take(self.raw) };
        if raw.is_null() {
            Err("dethv_snapshot_take failed".to_string())
        } else {
            Ok(DetSnapshot { raw })
        }
    }

    pub fn snapshot_restore(&mut self, snap: &DetSnapshot) -> Result<(), String> {
        let rc = unsafe { dethv_snapshot_restore(self.raw, snap.raw) };
        if rc == 0 { Ok(()) } else { Err("dethv_snapshot_restore failed".to_string()) }
    }

    pub fn stdout_bytes(&self) -> Vec<u8> {
        let mut len = 0usize;
        let ptr = unsafe { dethv_get_stdout(self.raw, &mut len) };
        if ptr.is_null() || len == 0 { return Vec::new(); }
        unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
    }

    pub fn stderr_bytes(&self) -> Vec<u8> {
        let mut len = 0usize;
        let ptr = unsafe { dethv_get_stderr(self.raw, &mut len) };
        if ptr.is_null() || len == 0 { return Vec::new(); }
        unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
    }

    pub fn stop_reason_name(reason: u32) -> String {
        unsafe { CStr::from_ptr(dethv_stop_reason_str(reason)).to_string_lossy().into_owned() }
    }
}

impl Drop for DetVm {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { dethv_destroy(self.raw) };
        }
    }
}
