use {
    bytes::{Bytes, BytesMut},
    curve25519_dalek::MontgomeryPoint,
    quinn_proto::{
        ClientConfig, Connection, ConnectionEvent, ConnectionHandle, ConnectionId,
        ConnectionIdGenerator, DatagramEvent, Endpoint, EndpointConfig, Event,
        IdleTimeout, ServerConfig, TransportConfig, Transmit, VarInt,
        crypto::{
            CryptoError, HandshakeTokenKey, HmacKey, UnsupportedVersion,
            rustls::{QuicClientConfig, QuicServerConfig},
        },
    },
    rand::{RngCore, SeedableRng},
    rand_chacha::ChaCha20Rng,
    rustls::{
        NamedGroup,
        crypto::{
            ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
            SupportedKxGroup,
        },
    },
    solana_keypair::Keypair,
    solana_sha256_hasher::hashv,
    solana_tls_utils::{
        SkipClientVerification, SkipServerVerification, new_dummy_x509_certificate,
    },
    std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    },
};

/* ================= Deterministic Crypto Primitives for Rustls + Quinn ================= */

pub const ALPENGLOW_ALPN: &[u8] = b"alpenglow-v1";

#[derive(Debug)]
struct DetSecureRandom {
    rng: Mutex<ChaCha20Rng>,
}

impl DetSecureRandom {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: Mutex::new(ChaCha20Rng::from_seed(seed)),
        }
    }

    fn next_bytes(&self, out: &mut [u8]) {
        self.rng.lock().unwrap().fill_bytes(out);
    }
}

impl SecureRandom for DetSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.next_bytes(buf);
        Ok(())
    }
}

#[derive(Debug)]
struct DetX25519Group {
    rng: Arc<DetSecureRandom>,
}

struct DetX25519Active {
    secret: [u8; 32],
    public: [u8; 32],
}

impl ActiveKeyExchange for DetX25519Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = MontgomeryPoint(peer).mul_clamped(self.secret).to_bytes();
        if shared == [0u8; 32] {
            return Err(rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare));
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl SupportedKxGroup for DetX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut secret = [0u8; 32];
        self.rng.next_bytes(&mut secret);
        let public = MontgomeryPoint::mul_base_clamped(secret).to_bytes();
        Ok(Box::new(DetX25519Active { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

fn deterministic_crypto_provider(seed: [u8; 32]) -> Arc<CryptoProvider> {
    let det_rng = Arc::new(DetSecureRandom::new(seed));
    let mut provider = rustls::crypto::ring::default_provider();
    let kx_static: &'static dyn SupportedKxGroup = Box::leak(Box::new(DetX25519Group {
        rng: det_rng.clone(),
    }));
    let rng_static: &'static dyn SecureRandom = Box::leak(Box::new(DetSecureRandom::new(seed)));
    provider.kx_groups = vec![kx_static];
    provider.secure_random = rng_static;
    Arc::new(provider)
}

/* Deterministic QUIC Connection ID Generator */
struct DetCidGenerator {
    prefix: u64,
    counter: AtomicU64,
}

impl ConnectionIdGenerator for DetCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; 8];
        let v = self.prefix ^ n.wrapping_mul(0x9e3779b97f4a7c15);
        bytes.copy_from_slice(&v.to_le_bytes());
        ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        8
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/* Deterministic HMAC & Handshake Token Keys for quinn-proto */
struct DetHmacKey([u8; 32]);

impl HmacKey for DetHmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let h = hashv(&[&self.0, data]);
        let n = signature_out.len().min(32);
        signature_out[..n].copy_from_slice(&h.as_ref()[..n]);
    }

    fn signature_len(&self) -> usize {
        16
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut expected = [0u8; 16];
        self.sign(data, &mut expected);
        if signature == expected {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

struct DetAeadKey([u8; 32]);

impl quinn_proto::crypto::AeadKey for DetAeadKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let tag = hashv(&[&self.0, additional_data, data]);
        data.extend_from_slice(&tag.as_ref()[..16]);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        if data.len() < 16 {
            return Err(CryptoError);
        }
        let split = data.len() - 16;
        let tag = hashv(&[&self.0, additional_data, &data[..split]]);
        if &data[split..] == &tag.as_ref()[..16] {
            Ok(&mut data[..split])
        } else {
            Err(CryptoError)
        }
    }
}

struct DetTokenKey([u8; 32]);

impl HandshakeTokenKey for DetTokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn quinn_proto::crypto::AeadKey> {
        let derived = hashv(&[&self.0, random_bytes]);
        Box::new(DetAeadKey(derived.to_bytes()))
    }
}

/* ================= Sans-IO Deterministic Alpenglow QUIC Endpoint ================= */

pub struct OutboundUdp {
    pub local_port: u16,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

pub struct DetQuicNode {
    local_port: u16,
    base_instant: Instant,
    endpoint: Endpoint,
    client_cfg: ClientConfig,
    conns: BTreeMap<ConnectionHandle, Connection>,
    outbound_conn: Option<ConnectionHandle>,
    tx_buf: Vec<u8>,
}

impl DetQuicNode {
    pub fn new(
        identity: &Keypair,
        local_port: u16,
        seed: [u8; 32],
        is_server: bool,
    ) -> Self {
        let provider = deterministic_crypto_provider(seed);
        let (cert, key) = new_dummy_x509_certificate(identity);

        let mut transport = TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
            .datagram_send_buffer_size(2 * 1024 * 1024)
            .initial_mtu(1280)
            .min_mtu(1280)
            .mtu_discovery_config(None)
            .keep_alive_interval(Some(Duration::from_secs(2)))
            .enable_segmentation_offload(false)
            .max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(30)).unwrap()))
            .max_concurrent_bidi_streams(VarInt::from(0u8))
            .max_concurrent_uni_streams(VarInt::from(0u8));
        let transport = Arc::new(transport);

        // Client TLS config
        let mut tls_client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_client_auth_cert(vec![cert.clone()], key.clone_key())
            .unwrap();
        tls_client.enable_early_data = false;
        tls_client.alpn_protocols = vec![ALPENGLOW_ALPN.to_vec()];
        let quic_client = QuicClientConfig::try_from(tls_client).unwrap();
        let mut client_cfg = ClientConfig::new(Arc::new(quic_client));
        client_cfg.transport_config(transport.clone());

        // Optional Server TLS config
        let server_cfg = if is_server {
            let mut tls_server = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(SkipClientVerification::new())
                .with_single_cert(vec![cert], key)
                .unwrap();
            tls_server.alpn_protocols = vec![ALPENGLOW_ALPN.to_vec()];
            tls_server.max_early_data_size = 0;
            let quic_server = QuicServerConfig::try_from(tls_server).unwrap();
            let mut sc = ServerConfig::new(
                Arc::new(quic_server),
                Arc::new(DetTokenKey(seed)),
            );
            sc.transport_config(transport);
            sc.migration(false);
            Some(Arc::new(sc))
        } else {
            None
        };

        let prefix = u64::from_le_bytes(seed[0..8].try_into().unwrap()) ^ (local_port as u64);
        let mut ep_cfg = EndpointConfig::new(Arc::new(DetHmacKey(seed)));
        ep_cfg.rng_seed(Some(seed));
        ep_cfg.cid_generator(move || {
            Box::new(DetCidGenerator {
                prefix,
                counter: AtomicU64::new(1),
            })
        });

        let endpoint = Endpoint::new(Arc::new(ep_cfg), server_cfg, false, Some(seed));

        Self {
            local_port,
            base_instant: Instant::now(),
            endpoint,
            client_cfg,
            conns: BTreeMap::new(),
            outbound_conn: None,
            tx_buf: Vec::with_capacity(4096),
        }
    }

    fn v_instant(&self, vmono_ns: u64) -> Instant {
        self.base_instant + Duration::from_nanos(vmono_ns)
    }

    pub fn connect(&mut self, vmono_ns: u64, remote: SocketAddr) -> Result<(), String> {
        let now = self.v_instant(vmono_ns);
        let (handle, conn) = self
            .endpoint
            .connect(now, self.client_cfg.clone(), remote, "alpenglow")
            .map_err(|e| format!("quinn connect failed: {e:?}"))?;
        self.conns.insert(handle, conn);
        self.outbound_conn = Some(handle);
        Ok(())
    }

    pub fn is_outbound_connected(&self) -> bool {
        if let Some(h) = self.outbound_conn
            && let Some(c) = self.conns.get(&h)
        {
            return !c.is_handshaking() && !c.is_closed();
        }
        false
    }

    pub fn is_outbound_started(&self) -> bool {
        if let Some(h) = self.outbound_conn
            && let Some(c) = self.conns.get(&h)
        {
            return !c.is_closed();
        }
        false
    }

    pub fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), String> {
        let Some(h) = self.outbound_conn else {
            return Err("no outbound QUIC connection".into());
        };
        let Some(c) = self.conns.get_mut(&h) else {
            return Err("outbound QUIC connection missing".into());
        };
        c.datagrams()
            .send(Bytes::from(data), true)
            .map_err(|e| format!("send_datagram failed: {e:?}"))
    }

    pub fn handle_udp(
        &mut self,
        vmono_ns: u64,
        remote: SocketAddr,
        local_ip: Ipv4Addr,
        payload: &[u8],
        out_udps: &mut Vec<OutboundUdp>,
        in_datagrams: &mut Vec<Vec<u8>>,
    ) {
        let now = self.v_instant(vmono_ns);
        let mut resp_buf = Vec::new();
        let data = BytesMut::from(payload);

        if let Some(ev) = self.endpoint.handle(
            now,
            remote,
            Some(IpAddr::V4(local_ip)),
            None,
            data,
            &mut resp_buf,
        ) {
            match ev {
                DatagramEvent::ConnectionEvent(handle, ce) => {
                    if let Some(conn) = self.conns.get_mut(&handle) {
                        conn.handle_event(ce);
                    }
                }
                DatagramEvent::NewConnection(incoming) => {
                    let mut abuf = Vec::new();
                    match self.endpoint.accept(incoming, now, &mut abuf, None) {
                        Ok((handle, conn)) => {
                            self.conns.insert(handle, conn);
                        }
                        Err(e) => {
                            if let Some(tr) = e.response {
                                self.push_transmit(tr, &abuf, out_udps);
                            }
                        }
                    }
                }
                DatagramEvent::Response(tr) => {
                    self.push_transmit(tr, &resp_buf, out_udps);
                }
            }
        }
        self.drive(vmono_ns, out_udps, in_datagrams);
    }

    pub fn drive(
        &mut self,
        vmono_ns: u64,
        out_udps: &mut Vec<OutboundUdp>,
        in_datagrams: &mut Vec<Vec<u8>>,
    ) {
        let now = self.v_instant(vmono_ns);
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        let mut pending_conn_events: Vec<(ConnectionHandle, ConnectionEvent)> = Vec::new();
        let mut closed_handles: Vec<ConnectionHandle> = Vec::new();

        for h in handles {
            let Some(conn) = self.conns.get_mut(&h) else { continue };
            if let Some(to) = conn.poll_timeout()
                && to <= now
            {
                conn.handle_timeout(now);
            }
            while let Some(ep_ev) = conn.poll_endpoint_events() {
                let is_drained = ep_ev.is_drained();
                if let Some(ce) = self.endpoint.handle_event(h, ep_ev) {
                    pending_conn_events.push((h, ce));
                }
                if is_drained {
                    closed_handles.push(h);
                }
            }
            while let Some(ev) = conn.poll() {
                if let Event::DatagramReceived = ev {
                    while let Some(dg) = conn.datagrams().recv() {
                        in_datagrams.push(dg.to_vec());
                    }
                }
            }
            loop {
                self.tx_buf.clear();
                let Some(tr) = conn.poll_transmit(now, 1, &mut self.tx_buf) else {
                    break;
                };
                let payload = self.tx_buf[..tr.size].to_vec();
                out_udps.push(OutboundUdp {
                    local_port: self.local_port,
                    dst: tr.destination,
                    payload,
                });
            }
        }

        for (h, ce) in pending_conn_events {
            if let Some(conn) = self.conns.get_mut(&h) {
                conn.handle_event(ce);
            }
        }

        for h in closed_handles {
            self.conns.remove(&h);
            if self.outbound_conn == Some(h) {
                self.outbound_conn = None;
            }
        }
    }

    fn push_transmit(&self, tr: Transmit, buf: &[u8], out_udps: &mut Vec<OutboundUdp>) {
        out_udps.push(OutboundUdp {
            local_port: self.local_port,
            dst: tr.destination,
            payload: buf[..tr.size].to_vec(),
        });
    }
}

/* Keep UnsupportedVersion imported if needed later */
#[allow(dead_code)]
fn _check_version(_: UnsupportedVersion) {}
