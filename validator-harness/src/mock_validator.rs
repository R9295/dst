use {
    crate::det_quic::{DetQuicNode, OutboundUdp},
    agave_votor_messages::{
        certificate::{Certificate, CertificateType},
        consensus_message::{BLS_KEYPAIR_DERIVE_SEED, Block, BlockId},
        vote::Vote,
        wire::{VersionedWireConsensusMessage, get_vote_payload_to_sign},
    },
    bitvec::prelude::*,
    serde::Serialize,
    solana_bls_signatures::{
        keypair::Keypair as BLSKeypair, pubkey::PubkeyCompressed as BLSPubkeyCompressed,
    },
    solana_clock::Slot,
    solana_core::repair::serve_repair::{
        BlockIdRepairResponse, FecSetRoot, RepairProtocol,
    },
    solana_entry::{
        block_component::{
            BlockComponent, BlockFooterV1, BlockHeaderV1, VersionedBlockMarker,
        },
        entry::next_entry,
    },
    solana_genesis_config::GenesisConfig,
    solana_gossip::{
        Protocol as GossipProtocol,
        contact_info::{ContactInfo, Protocol as CiProtocol},
        crds_data::CrdsData,
        crds_value::CrdsValue,
        ping_pong::{Ping, Pong},
    },
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_leader_schedule::{LeaderSchedule, NUM_CONSECUTIVE_LEADER_SLOTS, SlotLeader},
    solana_ledger::shred::{
        DATA_SHREDS_PER_FEC_BLOCK, ProcessShredsStats, Shred, Shredder,
        merkle_tree::{MerkleTree, get_proof_size},
    },
    solana_native_token::LAMPORTS_PER_SOL,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_runtime::{
        bank::Bank,
        block_component_processor::BlockComponentProcessor,
    },
    solana_sha256_hasher::hashv,
    solana_shred_version::compute_shred_version,
    solana_signer::Signer,
    solana_signer_store::encode_base2,
    solana_stake_interface::state::StakeStateV2,
    std::{
        collections::BTreeMap,
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
        process::Command,
        sync::Arc,
    },
};

pub const MOCK_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const TEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

pub const MOCK_GOSSIP_PORT: u16 = 8001;
pub const MOCK_TVU_PORT: u16 = 8002;
pub const MOCK_REPAIR_PORT: u16 = 8003;
pub const MOCK_ALPENGLOW_SRV_PORT: u16 = 8004;
pub const MOCK_ALPENGLOW_CLI_PORT: u16 = 8005;

pub const FIXED_GENESIS_CREATION_TIME_RFC3339: &str = "2023-11-14T22:13:20Z";
const FIXED_CONTACT_INFO_OUTSET: u64 = 1_700_000_000_000_000;

/* ================= Genesis Setup (60% Mock Leader + 40% Test Validator) ================= */

#[derive(Serialize)]
struct YamlValidatorAccountsFile {
    validator_accounts: Vec<YamlValidatorAccount>,
}

#[derive(Serialize)]
struct YamlValidatorAccount {
    balance_lamports: u64,
    stake_lamports: u64,
    identity_account: String,
    vote_account: String,
    stake_account: String,
    bls_pubkey: Option<String>,
}

#[allow(dead_code)]
pub struct ClusterSetup {
    pub work_dir: PathBuf,
    pub ledger_dir: PathBuf,
    pub test_identity_path: PathBuf,
    pub test_vote_path: PathBuf,

    pub mock_identity: Keypair,
    pub mock_vote: Keypair,
    pub mock_stake: Keypair,
    pub mock_bls: BLSKeypair,
    pub mock_rank: u16,

    pub test_identity: Keypair,
    pub test_vote: Keypair,
    pub test_stake: Keypair,
    pub test_bls: BLSKeypair,

    pub genesis_config: GenesisConfig,
    pub genesis_hash: Hash,
    pub shred_version: u16,
    pub mock_active_stake: u64,
    pub test_active_stake: u64,
}

fn det_keypair(tag: u8) -> Keypair {
    let h = hashv(&[b"dethv-mock-cluster-v1", &[tag]]);
    Keypair::new_from_array(h.to_bytes())
}

fn write_keypair_json(path: &Path, kp: &Keypair) -> Result<(), String> {
    let bytes: Vec<u8> = kp.to_bytes().to_vec();
    let json = serde_json::to_string(&bytes).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

impl ClusterSetup {
    pub fn create(work_dir: &Path, solana_genesis_bin: &Path) -> Result<Self, String> {
        let ledger_dir = work_dir.join("ledger");
        if ledger_dir.exists() {
            fs::remove_dir_all(&ledger_dir).map_err(|e| e.to_string())?;
        }
        fs::create_dir_all(&ledger_dir).map_err(|e| e.to_string())?;

        let mock_identity = det_keypair(1);
        let mock_vote = det_keypair(2);
        let mock_stake = det_keypair(3);
        let test_identity = det_keypair(4);
        let test_vote = det_keypair(5);
        let test_stake = det_keypair(6);
        let faucet_kp = det_keypair(7);

        // solana-genesis sets authorized_voter = identity_pubkey, so BLS keys derive from identity!
        let mock_bls = BLSKeypair::derive_from_signer(&mock_identity, BLS_KEYPAIR_DERIVE_SEED)
            .map_err(|e| format!("derive mock bls: {e:?}"))?;
        let test_bls = BLSKeypair::derive_from_signer(&test_identity, BLS_KEYPAIR_DERIVE_SEED)
            .map_err(|e| format!("derive test bls: {e:?}"))?;

        let mock_bls_compressed = BLSPubkeyCompressed(mock_bls.public.to_bytes_compressed());
        let test_bls_compressed = BLSPubkeyCompressed(test_bls.public.to_bytes_compressed());

        let test_identity_path = work_dir.join("test-identity.json");
        let test_vote_path = work_dir.join("test-vote.json");
        write_keypair_json(&test_identity_path, &test_identity)?;
        write_keypair_json(&test_vote_path, &test_vote)?;

        // Exact 60% / 40% active stake (compensating for stake account rent-exempt reserve!)
        let stake_rent = Rent::default().minimum_balance(StakeStateV2::size_of());
        let mock_active_target = 600 * LAMPORTS_PER_SOL;
        let test_active_target = 400 * LAMPORTS_PER_SOL;
        let mock_stake_lamports = mock_active_target + stake_rent;
        let test_stake_lamports = test_active_target + stake_rent;

        let validators_yaml = YamlValidatorAccountsFile {
            validator_accounts: vec![YamlValidatorAccount {
                balance_lamports: 5_000 * LAMPORTS_PER_SOL,
                stake_lamports: test_stake_lamports,
                identity_account: test_identity.pubkey().to_string(),
                vote_account: test_vote.pubkey().to_string(),
                stake_account: test_stake.pubkey().to_string(),
                bls_pubkey: Some(test_bls_compressed.to_string()),
            }],
        };
        let yaml_path = work_dir.join("validators.yaml");
        let yaml_text = serde_yaml::to_string(&validators_yaml).map_err(|e| e.to_string())?;
        fs::write(&yaml_path, yaml_text).map_err(|e| e.to_string())?;

        let output = Command::new(solana_genesis_bin)
            .arg("--ledger")
            .arg(&ledger_dir)
            .arg("--cluster-type")
            .arg("development")
            .arg("--creation-time")
            .arg(FIXED_GENESIS_CREATION_TIME_RFC3339)
            .arg("--bootstrap-validator")
            .arg(mock_identity.pubkey().to_string())
            .arg(mock_vote.pubkey().to_string())
            .arg(mock_stake.pubkey().to_string())
            .arg("--bootstrap-validator-bls-pubkey")
            .arg(mock_bls_compressed.to_string())
            .arg("--bootstrap-validator-lamports")
            .arg((5_000 * LAMPORTS_PER_SOL).to_string())
            .arg("--bootstrap-validator-stake-lamports")
            .arg(mock_stake_lamports.to_string())
            .arg("--validator-accounts-file")
            .arg(&yaml_path)
            .arg("--faucet-pubkey")
            .arg(faucet_kp.pubkey().to_string())
            .arg("--faucet-lamports")
            .arg((500_000_000 * LAMPORTS_PER_SOL).to_string())
            .output()
            .map_err(|e| format!("failed to run solana-genesis: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "solana-genesis failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let genesis_config = GenesisConfig::load(&ledger_dir)
            .map_err(|e| format!("GenesisConfig::load failed: {e}"))?;
        let genesis_hash = genesis_config.hash();
        let shred_version = compute_shred_version(&genesis_hash, None);

        // Verify exact stake distribution, BLS rank map, and Epoch 0 leader schedule!
        let bank0 = Bank::new_for_benches(&genesis_config);
        let epoch_stakes = bank0
            .epoch_stakes(0)
            .ok_or("missing epoch 0 stakes in genesis bank")?;
        let vote_accounts = epoch_stakes.stakes().vote_accounts().inner();
        let mock_active_stake = vote_accounts
            .get(&mock_vote.pubkey())
            .map(|(s, _)| *s)
            .unwrap_or(0);
        let test_active_stake = vote_accounts
            .get(&test_vote.pubkey())
            .map(|(s, _)| *s)
            .unwrap_or(0);
        let total_stake = epoch_stakes.total_stake();
        assert_eq!(mock_active_stake, mock_active_target, "mock active stake mismatch");
        assert_eq!(test_active_stake, test_active_target, "test active stake mismatch");
        assert_eq!(total_stake, mock_active_target + test_active_target, "total stake mismatch");
        assert_eq!(mock_active_stake * 100 / total_stake, 60, "mock stake must be 60%");

        let rank_map = epoch_stakes.bls_pubkey_to_rank_map();
        let mock_rank = *rank_map
            .get_rank_for_vote_pubkey(&mock_vote.pubkey())
            .ok_or("mock validator missing from BLS rank map")?;

        let slots_in_epoch = bank0.epoch_schedule().get_slots_in_epoch(0) as usize;
        let leader_schedule = LeaderSchedule::new(
            vote_accounts,
            0,
            slots_in_epoch,
            NUM_CONSECUTIVE_LEADER_SLOTS,
        );
        for s in 0..12u64 {
            assert_eq!(
                leader_schedule[s].id,
                mock_identity.pubkey(),
                "expected mock validator to be leader for slot {s}"
            );
        }

        Ok(Self {
            work_dir: work_dir.to_path_buf(),
            ledger_dir,
            test_identity_path,
            test_vote_path,
            mock_identity,
            mock_vote,
            mock_stake,
            mock_bls,
            mock_rank,
            test_identity,
            test_vote,
            test_stake,
            test_bls,
            genesis_config,
            genesis_hash,
            shred_version,
            mock_active_stake,
            test_active_stake,
        })
    }
}

/* ================= Built Alpenglow Block + Shreds + Double-Merkle Proofs ================= */

#[allow(dead_code)]
pub struct BuiltBlock {
    pub slot: Slot,
    pub parent_slot: Slot,
    pub parent_block_id: BlockId,
    pub block_id: BlockId,
    pub bank_hash: Hash,
    pub last_blockhash: Hash,
    pub fec_set_count: u32,
    pub fec_set_roots: Vec<Hash>,
    pub double_merkle_proofs: Vec<Vec<u8>>, // 0..fec_set_count + parent leaf at index fec_set_count
    pub data_shreds: BTreeMap<u32, Vec<u8>>,
    pub code_shreds: BTreeMap<u32, Vec<u8>>,
    pub last_merkle_root: Hash,
    pub bank: Arc<Bank>,
}

/* ================= Deterministic Mock Validator ================= */

#[derive(Default, Debug, Clone)]
pub struct MockStats {
    pub gossip_rx: u64,
    pub gossip_tx: u64,
    pub turbine_shreds_sent: u64,
    pub repair_rx: u64,
    pub repair_tx: u64,
    pub certs_sent: u64,
    pub votor_votes_rx: u64,
    pub blocks_built: u64,
}

pub struct MockValidator {
    identity: Keypair,
    vote_pubkey: Pubkey,
    bls_keypair: BLSKeypair,
    rank: u16,
    shred_version: u16,

    // Peer (agave-validator) discovered info
    test_pubkey: Pubkey,
    peer_gossip_addr: SocketAddr,
    peer_tvu_addr: Option<SocketAddr>,
    peer_repair_addr: Option<SocketAddr>,
    peer_alpenglow_addr: Option<SocketAddr>,
    peer_ping_sent: bool,
    peer_discovered: bool,

    // Deterministic sans-IO QUIC endpoints for Alpenglow Votor
    quic_server: DetQuicNode, // 10.0.0.1:8004 (receives test validator's votes)
    quic_client: DetQuicNode, // 10.0.0.1:8005 (sends mock's NotarCert + FinalizeCert)

    // Built blocks & chain state
    root_bank: Arc<Bank>,
    pub blocks: BTreeMap<Slot, BuiltBlock>,
    next_slot_to_build: Slot,
    max_slots_to_build: Slot,
    next_block_time_ns: u64,
    next_gossip_push_ns: u64,
    next_cert_resend_ns: u64,
    slot_interval_ns: u64,
    withhold_for_repair_slots: Vec<Slot>,

    // Outbound UDP queue waiting to be injected into DetHV
    pub pending_tx: Vec<OutboundUdp>,
    pub stats: MockStats,
    prng_counter: u64,
}

impl MockValidator {
    pub fn new(setup: &ClusterSetup, max_slots_to_build: Slot) -> Self {
        let root_bank = Arc::new(Bank::new_for_benches(&setup.genesis_config));
        let quic_srv_seed = hashv(&[b"dethv-quic-srv", setup.genesis_hash.as_ref()]).to_bytes();
        let quic_cli_seed = hashv(&[b"dethv-quic-cli", setup.genesis_hash.as_ref()]).to_bytes();

        Self {
            identity: setup.mock_identity.insecure_clone(),
            vote_pubkey: setup.mock_vote.pubkey(),
            bls_keypair: BLSKeypair::derive_from_signer(&setup.mock_identity, BLS_KEYPAIR_DERIVE_SEED)
                .expect("derive mock bls"),
            rank: setup.mock_rank,
            shred_version: setup.shred_version,
            test_pubkey: setup.test_identity.pubkey(),
            peer_gossip_addr: SocketAddr::new(IpAddr::V4(TEST_IP), 8001),
            peer_tvu_addr: None,
            peer_repair_addr: None,
            peer_alpenglow_addr: None,
            peer_ping_sent: false,
            peer_discovered: false,
            quic_server: DetQuicNode::new(&setup.mock_identity, MOCK_ALPENGLOW_SRV_PORT, quic_srv_seed, true),
            quic_client: DetQuicNode::new(&setup.mock_identity, MOCK_ALPENGLOW_CLI_PORT, quic_cli_seed, false),
            root_bank,
            blocks: BTreeMap::new(),
            next_slot_to_build: 1,
            max_slots_to_build,
            next_block_time_ns: 0,
            next_gossip_push_ns: 0,
            next_cert_resend_ns: 0,
            slot_interval_ns: 250_000_000, // 250 ms virtual time per slot
            // Intentionally withhold 1 data shred on even slots to exercise Repair alongside Turbine!
            withhold_for_repair_slots: vec![2, 4, 6, 8],
            pending_tx: Vec::new(),
            stats: MockStats::default(),
            prng_counter: 1,
        }
    }

    fn det_token32(&mut self) -> [u8; 32] {
        let n = self.prng_counter;
        self.prng_counter += 1;
        hashv(&[b"dethv-gossip-ping-token", &n.to_le_bytes()]).to_bytes()
    }

    fn build_deterministic_contact_info(&self, wallclock_ms: u64) -> ContactInfo {
        // Construct ContactInfo with fixed deterministic outset (zero host SystemTime!)
        let dummy = ContactInfo::new(self.identity.pubkey(), 0, self.shred_version);
        let mut raw = wincode::serialize(&dummy).expect("serialize dummy ContactInfo");
        // Wire layout: [pubkey: 32B][wallclock=0: 1B (0x00)][outset: 8B LE]...
        raw[33..41].copy_from_slice(&FIXED_CONTACT_INFO_OUTSET.to_le_bytes());
        let mut ci: ContactInfo = wincode::deserialize(&raw).expect("deserialize deterministic ContactInfo");
        ci.set_wallclock(wallclock_ms);
        ci.set_gossip((MOCK_IP, MOCK_GOSSIP_PORT)).unwrap();
        ci.set_tvu(CiProtocol::UDP, (MOCK_IP, MOCK_TVU_PORT)).unwrap();
        ci.set_serve_repair(CiProtocol::UDP, (MOCK_IP, MOCK_REPAIR_PORT)).unwrap();
        ci.set_alpenglow((MOCK_IP, MOCK_ALPENGLOW_SRV_PORT)).unwrap();
        ci
    }

    fn mock_crds_contact_info(&self, wallclock_ms: u64) -> CrdsValue {
        let ci = self.build_deterministic_contact_info(wallclock_ms);
        CrdsValue::new(CrdsData::ContactInfo(ci), &self.identity)
    }

    fn push_udp(&mut self, local_port: u16, dst: SocketAddr, payload: Vec<u8>) {
        self.pending_tx.push(OutboundUdp {
            local_port,
            dst,
            payload,
        });
    }

    /* ==================== Inbound Packet Dispatch from Guest ==================== */

    pub fn on_guest_udp(
        &mut self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        vmono_ns: u64,
        vtime_ns: u64,
    ) {
        let remote = SocketAddr::new(IpAddr::V4(src_ip), src_port);
        let wallclock_ms = vtime_ns / 1_000_000;

        match dst_port {
            MOCK_GOSSIP_PORT => self.handle_gossip(remote, payload, wallclock_ms),
            MOCK_REPAIR_PORT => self.handle_repair(remote, payload),
            MOCK_ALPENGLOW_SRV_PORT => {
                let mut in_dgs = Vec::new();
                self.quic_server.handle_udp(
                    vmono_ns,
                    remote,
                    MOCK_IP,
                    payload,
                    &mut self.pending_tx,
                    &mut in_dgs,
                );
                self.stats.votor_votes_rx += in_dgs.len() as u64;
            }
            MOCK_ALPENGLOW_CLI_PORT => {
                let mut in_dgs = Vec::new();
                self.quic_client.handle_udp(
                    vmono_ns,
                    remote,
                    MOCK_IP,
                    payload,
                    &mut self.pending_tx,
                    &mut in_dgs,
                );
            }
            _ => {}
        }
    }

    fn handle_gossip(&mut self, from: SocketAddr, payload: &[u8], wallclock_ms: u64) {
        self.stats.gossip_rx += 1;
        let Ok(msg) = wincode::deserialize::<GossipProtocol>(payload) else {
            return;
        };

        match msg {
            GossipProtocol::PingMessage(ping) => {
                let pong = Pong::new(&ping, &self.identity);
                if let Ok(bytes) = wincode::serialize(&GossipProtocol::PongMessage(pong)) {
                    self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                    self.stats.gossip_tx += 1;
                }
                // Immediately push our ContactInfo right after answering their Ping!
                let ci_val = self.mock_crds_contact_info(wallclock_ms);
                let push = GossipProtocol::PushMessage(self.identity.pubkey(), vec![ci_val]);
                if let Ok(bytes) = wincode::serialize(&push) {
                    self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                    self.stats.gossip_tx += 1;
                }
            }
            GossipProtocol::PongMessage(_pong) => {
                // Peer verified; send our ContactInfo via Push
                let ci_val = self.mock_crds_contact_info(wallclock_ms);
                let push = GossipProtocol::PushMessage(self.identity.pubkey(), vec![ci_val]);
                if let Ok(bytes) = wincode::serialize(&push) {
                    self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                    self.stats.gossip_tx += 1;
                }
            }
            GossipProtocol::PullRequest(_filter, caller_val) => {
                self.inspect_crds_value(&caller_val);
                let ci_val = self.mock_crds_contact_info(wallclock_ms);
                let resp = GossipProtocol::PullResponse(self.identity.pubkey(), vec![ci_val]);
                if let Ok(bytes) = wincode::serialize(&resp) {
                    self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                    self.stats.gossip_tx += 1;
                }
                if !self.peer_ping_sent {
                    self.peer_ping_sent = true;
                    let token = self.det_token32();
                    let ping = Ping::new(token, &self.identity);
                    if let Ok(bytes) = wincode::serialize(&GossipProtocol::PingMessage(ping)) {
                        self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                        self.stats.gossip_tx += 1;
                    }
                }
            }
            GossipProtocol::PushMessage(_from_pk, values)
            | GossipProtocol::PullResponse(_from_pk, values) => {
                for v in &values {
                    self.inspect_crds_value(v);
                }
                // Reply with our ContactInfo so peer learns our TVU/ServeRepair/Alpenglow ports
                let ci_val = self.mock_crds_contact_info(wallclock_ms);
                let push = GossipProtocol::PushMessage(self.identity.pubkey(), vec![ci_val]);
                if let Ok(bytes) = wincode::serialize(&push) {
                    self.push_udp(MOCK_GOSSIP_PORT, from, bytes);
                    self.stats.gossip_tx += 1;
                }
            }
            GossipProtocol::PruneMessage(_, _) => {}
        }
    }

    fn inspect_crds_value(&mut self, val: &CrdsValue) {
        if let CrdsData::ContactInfo(ci) = val.data()
            && *ci.pubkey() == self.test_pubkey
        {
            if let Some(g) = ci.gossip() {
                self.peer_gossip_addr = g;
            }
            if let Some(tvu) = ci.tvu(CiProtocol::UDP) {
                self.peer_tvu_addr = Some(tvu);
            }
            if let Some(sr) = ci.serve_repair(CiProtocol::UDP) {
                self.peer_repair_addr = Some(sr);
            }
            if let Some(alp) = ci.alpenglow() {
                self.peer_alpenglow_addr = Some(alp);
            }
            if !self.peer_discovered
                && self.peer_tvu_addr.is_some()
                && self.peer_alpenglow_addr.is_some()
            {
                self.peer_discovered = true;
                eprintln!(
                    "[mock] Discovered test validator ContactInfo: gossip={} tvu={:?} repair={:?} alpenglow={:?} shred_ver={}",
                    self.peer_gossip_addr,
                    self.peer_tvu_addr,
                    self.peer_repair_addr,
                    self.peer_alpenglow_addr,
                    ci.shred_version()
                );
            }
        }
    }

    /* ==================== Repair Server (10.0.0.1:8003) ==================== */

    fn send_repair_bytes(&mut self, dst: SocketAddr, mut bytes: Vec<u8>, nonce: u32) {
        bytes.extend_from_slice(&nonce.to_le_bytes());
        self.push_udp(MOCK_REPAIR_PORT, dst, bytes);
        self.stats.repair_tx += 1;
    }

    fn handle_repair(&mut self, from: SocketAddr, payload: &[u8]) {
        self.stats.repair_rx += 1;
        let Ok(req) = wincode::deserialize::<RepairProtocol>(payload) else {
            return;
        };
        match req {
            RepairProtocol::WindowIndex {
                header,
                slot,
                shred_index,
            } => {
                if let Some(blk) = self.blocks.get(&slot)
                    && let Some(shred) = blk.data_shreds.get(&(shred_index as u32)).cloned()
                {
                    self.send_repair_bytes(from, shred, header.nonce());
                }
            }
            RepairProtocol::WindowIndexForBlockId {
                header,
                slot,
                shred_index,
                block_id,
            } => {
                if let Some(blk) = self.blocks.get(&slot)
                    && blk.block_id == block_id
                    && let Some(shred) = blk.data_shreds.get(&shred_index).cloned()
                {
                    self.send_repair_bytes(from, shred, header.nonce());
                }
            }
            RepairProtocol::HighestWindowIndex {
                header,
                slot,
                shred_index,
            } => {
                if let Some(blk) = self.blocks.get(&slot)
                    && let Some((&hi_idx, shred)) = blk.data_shreds.iter().next_back()
                    && (hi_idx as u64) >= shred_index
                {
                    let shred = shred.clone();
                    self.send_repair_bytes(from, shred, header.nonce());
                }
            }
            RepairProtocol::Orphan { header, slot } => {
                let mut cur = slot;
                let mut to_send = Vec::new();
                for _ in 0..11 {
                    let Some(blk) = self.blocks.get(&cur) else { break };
                    if let Some((_, shred)) = blk.data_shreds.iter().next_back() {
                        to_send.push(shred.clone());
                    }
                    if blk.parent_slot == 0 {
                        break;
                    }
                    cur = blk.parent_slot;
                }
                for shred in to_send {
                    self.send_repair_bytes(from, shred, header.nonce());
                }
            }
            RepairProtocol::ParentAndFecSetCount {
                header,
                slot,
                block_id,
            } => {
                if let Some(blk) = self.blocks.get(&slot)
                    && blk.block_id == block_id
                {
                    let parent_proof = blk
                        .double_merkle_proofs
                        .get(blk.fec_set_count as usize)
                        .cloned()
                        .unwrap_or_default();
                    let resp = BlockIdRepairResponse::ParentFecSetCount {
                        fec_set_count: blk.fec_set_count,
                        parent_info: (blk.parent_slot, blk.parent_block_id.to_hash()),
                        parent_proof,
                    };
                    if let Ok(bytes) = wincode::serialize(&resp) {
                        self.send_repair_bytes(from, bytes, header.nonce());
                    }
                }
            }
            RepairProtocol::FecSetRoot {
                header,
                slot,
                block_id,
                fec_set_index,
            } => {
                let proof_idx = (fec_set_index as usize) / DATA_SHREDS_PER_FEC_BLOCK;
                if let Some(blk) = self.blocks.get(&slot)
                    && blk.block_id == block_id
                    && let Some(&root) = blk.fec_set_roots.get(proof_idx)
                    && let Some(proof) = blk.double_merkle_proofs.get(proof_idx).cloned()
                {
                    let resp = BlockIdRepairResponse::FecSetRoot {
                        fec_set_root: FecSetRoot::from(root),
                        fec_set_proof: proof,
                    };
                    if let Ok(bytes) = wincode::serialize(&resp) {
                        self.send_repair_bytes(from, bytes, header.nonce());
                    }
                }
            }
            RepairProtocol::Pong(_) | _ => {}
        }
    }

    /* ==================== Block Builder (Exact Alpenglow Format) ==================== */

    fn build_next_block(&mut self) -> Slot {
        let slot = self.next_slot_to_build;
        self.next_slot_to_build += 1;

        let (parent_slot, parent_block_id, parent_bank, parent_last_blockhash, mut chained_root) =
            if slot == 1 {
                (
                    0u64,
                    BlockId::default(),
                    self.root_bank.clone(),
                    self.root_bank.last_blockhash(),
                    Hash::default(),
                )
            } else {
                let prev = self.blocks.get(&(slot - 1)).expect("previous block exists");
                (
                    prev.slot,
                    prev.block_id,
                    prev.bank.clone(),
                    prev.last_blockhash,
                    prev.last_merkle_root,
                )
            };

        let bank = Arc::new(Bank::new_from_parent(
            parent_bank.clone(),
            SlotLeader {
                id: self.identity.pubkey(),
                vote_address: self.vote_pubkey,
            },
            slot,
        ));
        bank.set_tick_height(bank.max_tick_height() - 1);

        // Compute valid deterministic nanosecond timestamp within Alpenglow bounds
        let parent_time_nanos = parent_bank
            .get_nanosecond_clock()
            .unwrap_or_else(|| bank.clock().unix_timestamp.saturating_mul(1_000_000_000));
        let elapsed_ns = bank.slot_range_duration_nanos(parent_slot + 1, slot);
        let producer_time_nanos = parent_time_nanos.saturating_add(elapsed_ns as i64);

        // Apply footer clock/vote fields identically to BlockCreationLoop
        BlockComponentProcessor::update_bank_with_footer_fields(
            &bank,
            producer_time_nanos,
            None,
            None,
            None,
        )
        .expect("update_bank_with_footer_fields");

        // Single Alpentick (num_hashes = 1, empty txs)
        let alpentick = next_entry(&parent_last_blockhash, 1, vec![]);
        bank.register_tick_for_test(&alpentick.hash);
        bank.freeze();
        let bank_hash = bank.hash();

        // Shred 3 components: BlockHeaderV1 -> BlockFooterV1 -> Alpentick
        let shredder = Shredder::new(slot, parent_slot, 0, self.shred_version)
            .expect("Shredder::new");
        let mut stats = ProcessShredsStats::default();
        let mut next_data_idx = 0u32;
        let mut next_code_idx = 0u32;
        let mut data_shreds = BTreeMap::new();
        let mut code_shreds = BTreeMap::new();
        let mut fec_set_roots = Vec::new();

        // 1. BlockHeaderV1
        let header = BlockComponent::BlockMarker(VersionedBlockMarker::from_block_header(
            BlockHeaderV1 {
                parent_slot,
                parent_block_id,
            },
        ));
        let hdr_shreds = shredder.make_merkle_shreds_from_component(
            &self.identity,
            &header,
            false,
            chained_root,
            next_data_idx,
            next_code_idx,
            &mut stats,
        );
        chained_root = Self::collect_fec_shreds(
            hdr_shreds,
            &mut data_shreds,
            &mut code_shreds,
            &mut next_data_idx,
            &mut next_code_idx,
            &mut fec_set_roots,
        );

        // 2. BlockFooterV1
        let footer = BlockComponent::BlockMarker(VersionedBlockMarker::from_block_footer(
            BlockFooterV1 {
                bank_hash,
                block_producer_time_nanos: producer_time_nanos as u64,
                block_user_agent: b"dethv-mock-validator/5.0".to_vec(),
                block_final_cert: None,
                skip_reward_cert: None,
                notar_reward_cert: None,
            },
        ));
        let ftr_shreds = shredder.make_merkle_shreds_from_component(
            &self.identity,
            &footer,
            false,
            chained_root,
            next_data_idx,
            next_code_idx,
            &mut stats,
        );
        chained_root = Self::collect_fec_shreds(
            ftr_shreds,
            &mut data_shreds,
            &mut code_shreds,
            &mut next_data_idx,
            &mut next_code_idx,
            &mut fec_set_roots,
        );

        // 3. Alpentick (final component, is_last_in_slot = true)
        let tick_shreds = shredder.make_merkle_shreds_from_entries(
            &self.identity,
            std::slice::from_ref(&alpentick),
            true,
            chained_root,
            next_data_idx,
            next_code_idx,
            &mut stats,
        );
        let last_merkle_root = Self::collect_fec_shreds(
            tick_shreds,
            &mut data_shreds,
            &mut code_shreds,
            &mut next_data_idx,
            &mut next_code_idx,
            &mut fec_set_roots,
        );

        // Compute exact Double Merkle Root (Alpenglow block_id) & proofs
        let fec_set_count = fec_set_roots.len() as u32;
        let parent_leaf = hashv(&[
            &parent_slot.to_le_bytes(),
            parent_block_id.as_bytes(),
            &fec_set_count.to_le_bytes(),
        ]);
        let leaves = fec_set_roots
            .iter()
            .copied()
            .chain(std::iter::once(parent_leaf))
            .map(Ok);
        let tree_size = fec_set_count as usize + 1;
        let tree = MerkleTree::try_new_with_len(leaves, tree_size)
            .expect("Double Merkle tree construction");
        let block_id = BlockId::from(*tree.root());
        let proof_len =
            get_proof_size(tree_size) as usize * agave_shred_wire_format::constants::SIZE_OF_MERKLE_PROOF_ENTRY;
        let mut double_merkle_proofs = Vec::with_capacity(tree_size);
        for leaf_i in 0..tree_size {
            let mut p = Vec::with_capacity(proof_len);
            for entry in tree.make_merkle_proof(leaf_i, tree_size) {
                p.extend_from_slice(entry.expect("proof entry"));
            }
            double_merkle_proofs.push(p);
        }

        bank.set_block_id(Some(block_id));

        eprintln!(
            "[mock] Built slot {slot}: parent={parent_slot} block_id={block_id} bank_hash={bank_hash} data_shreds={} code_shreds={}",
            data_shreds.len(),
            code_shreds.len()
        );

        self.blocks.insert(
            slot,
            BuiltBlock {
                slot,
                parent_slot,
                parent_block_id,
                block_id,
                bank_hash,
                last_blockhash: alpentick.hash,
                fec_set_count,
                fec_set_roots,
                double_merkle_proofs,
                data_shreds,
                code_shreds,
                last_merkle_root,
                bank,
            },
        );
        self.stats.blocks_built += 1;
        slot
    }

    fn collect_fec_shreds(
        shreds: Vec<Shred>,
        data_out: &mut BTreeMap<u32, Vec<u8>>,
        code_out: &mut BTreeMap<u32, Vec<u8>>,
        next_data_idx: &mut u32,
        next_code_idx: &mut u32,
        fec_roots: &mut Vec<Hash>,
    ) -> Hash {
        let mut last_root = Hash::default();
        let mut seen_fec = BTreeMap::<u32, Hash>::new();
        for s in shreds {
            let fec = s.fec_set_index();
            if let Ok(mr) = s.merkle_root() {
                seen_fec.entry(fec).or_insert(mr);
                last_root = mr;
            }
            if s.is_data() {
                let idx = s.index();
                *next_data_idx = (*next_data_idx).max(idx + 1);
                data_out.insert(idx, s.payload().to_vec());
            } else {
                let idx = s.index();
                *next_code_idx = (*next_code_idx).max(idx + 1);
                code_out.insert(idx, s.payload().to_vec());
            }
        }
        for (_, r) in seen_fec {
            fec_roots.push(r);
        }
        last_root
    }

    /* ==================== Turbine Broadcast & Alpenglow Certificates ==================== */

    fn broadcast_block_via_turbine(&mut self, slot: Slot) {
        let Some(tvu_addr) = self.peer_tvu_addr else { return };
        let withhold_repair = self.withhold_for_repair_slots.contains(&slot);
        let Some(blk) = self.blocks.get(&slot) else { return };

        let mut packets = Vec::new();
        for (&idx, bytes) in &blk.data_shreds {
            // Withhold data shred #1 on selected slots so agave-validator actively uses Repair!
            if withhold_repair && idx == 1 {
                continue;
            }
            packets.push(bytes.clone());
        }
        // On non-repair slots, also broadcast coding shreds for FEC set 0 (realistic Turbine!)
        if !withhold_repair {
            for (&idx, bytes) in blk.code_shreds.iter().take(4) {
                let _ = idx;
                packets.push(bytes.clone());
            }
        }

        for p in packets {
            self.push_udp(MOCK_TVU_PORT, tvu_addr, p);
            self.stats.turbine_shreds_sent += 1;
        }
    }

    fn make_single_validator_bitmap(&self) -> Vec<u8> {
        let mut bv: BitVec<u8, Lsb0> = BitVec::repeat(false, (self.rank as usize) + 1);
        bv.set(self.rank as usize, true);
        encode_base2(&bv).expect("encode_base2")
    }

    fn send_certs_for_slot(&mut self, slot: Slot) {
        if !self.quic_client.is_outbound_connected() {
            return;
        }
        let Some(blk) = self.blocks.get(&slot) else { return };
        let block = Block {
            slot,
            block_id: blk.block_id,
        };
        let bitmap = self.make_single_validator_bitmap();

        // 1. Notarize Certificate (60% >= 60% threshold!)
        let notar_payload = get_vote_payload_to_sign(Vote::new_notarization_vote(block), self.shred_version);
        let notar_sig = self.bls_keypair.sign(&notar_payload);
        let notar_cert = Certificate {
            cert_type: CertificateType::Notarize(block),
            signature: notar_sig.into(),
            bitmap: bitmap.clone(),
        };
        let wire_notar = VersionedWireConsensusMessage::new_from_cert(notar_cert, self.shred_version);
        if let Ok(bytes) = wincode::serialize(&wire_notar)
            && self.quic_client.send_datagram(bytes).is_ok()
        {
            self.stats.certs_sent += 1;
        }

        // 2. Finalize Certificate (60% >= 60% threshold! Together with NotarizeCert -> Slow Finalization!)
        let fin_payload = get_vote_payload_to_sign(Vote::new_finalization_vote(slot), self.shred_version);
        let fin_sig = self.bls_keypair.sign(&fin_payload);
        let fin_cert = Certificate {
            cert_type: CertificateType::Finalize(slot),
            signature: fin_sig.into(),
            bitmap,
        };
        let wire_fin = VersionedWireConsensusMessage::new_from_cert(fin_cert, self.shred_version);
        if let Ok(bytes) = wincode::serialize(&wire_fin)
            && self.quic_client.send_datagram(bytes).is_ok()
        {
            self.stats.certs_sent += 1;
        }
    }

    /* ==================== Periodic Deterministic Tick ==================== */

    pub fn tick(&mut self, vmono_ns: u64, vtime_ns: u64, highest_rooted_slot: Slot) {
        let wallclock_ms = vtime_ns / 1_000_000;

        // Periodically push Mock ContactInfo to test validator's gossip port
        if vmono_ns >= self.next_gossip_push_ns {
            self.next_gossip_push_ns = vmono_ns + 500_000_000;
            let ci_val = self.mock_crds_contact_info(wallclock_ms);
            let push = GossipProtocol::PushMessage(self.identity.pubkey(), vec![ci_val]);
            if let Ok(bytes) = wincode::serialize(&push) {
                self.push_udp(MOCK_GOSSIP_PORT, self.peer_gossip_addr, bytes);
                self.stats.gossip_tx += 1;
            }
        }

        // Establish deterministic mTLS QUIC connection to test validator's Alpenglow port once discovered
        if let Some(alp_addr) = self.peer_alpenglow_addr
            && !self.quic_client.is_outbound_started()
        {
            if let Err(e) = self.quic_client.connect(vmono_ns, alp_addr) {
                eprintln!("[mock] QUIC connect error: {e}");
            } else {
                eprintln!("[mock] Initiating deterministic mTLS QUIC handshake to {alp_addr}");
            }
        }

        // Once peer is discovered and QUIC connected, build & serve slots 1..=max_slots_to_build
        if self.peer_discovered && self.quic_client.is_outbound_connected() {
            if self.next_block_time_ns == 0 {
                self.next_block_time_ns = vmono_ns;
            }
            if self.next_slot_to_build <= self.max_slots_to_build
                && vmono_ns >= self.next_block_time_ns
            {
                let s = self.build_next_block();
                self.broadcast_block_via_turbine(s);
                self.send_certs_for_slot(s);
                self.next_block_time_ns = vmono_ns + self.slot_interval_ns;
            }

            // Re-send certificates for any unrooted built slots every 400ms (QUIC datagrams are unreliable)
            if vmono_ns >= self.next_cert_resend_ns {
                self.next_cert_resend_ns = vmono_ns + 400_000_000;
                let slots: Vec<Slot> = self
                    .blocks
                    .keys()
                    .copied()
                    .filter(|&s| s > highest_rooted_slot)
                    .collect();
                for s in slots {
                    self.send_certs_for_slot(s);
                }
            }
        }

        // Drive sans-IO QUIC timers & flush packets
        let mut in_srv = Vec::new();
        self.quic_server
            .drive(vmono_ns, &mut self.pending_tx, &mut in_srv);
        self.stats.votor_votes_rx += in_srv.len() as u64;

        let mut in_cli = Vec::new();
        self.quic_client
            .drive(vmono_ns, &mut self.pending_tx, &mut in_cli);
    }
}
