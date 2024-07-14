use log::{error, info};
use std::io;
use std::iter::Chain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::ops::RangeInclusive;
use std::process::exit;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::Duration;
use thiserror::Error;

type Port = u16;
type PortRange = RangeInclusive<Port>;

#[derive(Debug, Error)]
enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("hickory_resolver resolve error: {0}")]
    HickoryResolve(#[from] hickory_resolver::error::ResolveError),

    #[error("no ipv6 address resolved")]
    NoIpv6Resolve,

    #[error("incoming traffic from blacklisted source IP address")]
    ExternalSourceBlacklisted,

    #[error("incoming traffic from an IP address that does not belong to the external hostname")]
    ExternalSourceInvalid,

    #[error("failed to lock mutex: {0}")]
    MutexLock(#[from] TryLockError<MutexGuard<'static, proxy::External>>),
}

type Result<T> = std::result::Result<T, Error>;

mod config {
    use super::*;

    pub const MAX_PACKET_BYTES: usize = 1500;

    pub const INTERNAL: Ipv4Addr = Ipv4Addr::new(10, 128, 40, 252);
    pub const EXTERNAL: &str = "06028.sip.arcor.de";

    pub const EXTERNAL_FLOWINFO: u32 = 0;
    pub const EXTERNAL_SCOPE_ID: u32 = 0;

    pub const NAMESERVER: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
        53,
        EXTERNAL_FLOWINFO,
        EXTERNAL_SCOPE_ID,
    )); // Quad9

    const SIP_PORTS: PortRange = 5060..=5080;
    const RTP_PORTS: PortRange = 16384..=16482;

    pub fn ports() -> Chain<PortRange, PortRange> {
        SIP_PORTS.chain(RTP_PORTS)
    }
}

mod dns {
    use super::*;
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    use hickory_resolver::Resolver;

    pub fn resolve_ipv6(hostname: &str) -> Result<Ipv6Addr> {
        let mut cfg = ResolverConfig::new();

        cfg.add_name_server(NameServerConfig::new(config::NAMESERVER, Protocol::Udp));

        let resolver = Resolver::new(cfg, ResolverOpts::default())?;
        let response = resolver.lookup_ip(hostname)?;

        while let Some(ip_addr) = response.iter().next() {
            if let IpAddr::V6(ipv6_addr) = ip_addr {
                return Ok(ipv6_addr);
            }
        }

        Err(Error::NoIpv6Resolve)
    }
}

mod proxy {
    use super::*;

    pub struct External {
        addr: Ipv6Addr,
        ignore: Vec<Ipv6Addr>,
    }

    impl External {
        pub fn new() -> Result<External> {
            Ok(External {
                addr: dns::resolve_ipv6(config::EXTERNAL)?,
                ignore: Vec::new(),
            })
        }

        pub fn is(&mut self, other: Ipv6Addr) -> Result<()> {
            if self.addr == other {
                return Ok(());
            }

            if self.ignore.contains(&other) {
                return Err(Error::ExternalSourceBlacklisted);
            }

            self.addr = dns::resolve_ipv6(config::EXTERNAL)?;

            if self.addr == other {
                return Ok(());
            } else {
                self.ignore.push(other);
                return Err(Error::ExternalSourceInvalid);
            }
        }

        pub fn addr(&self) -> Ipv6Addr {
            self.addr
        }

        pub fn socket_addr(&self, port: Port) -> SocketAddrV6 {
            SocketAddrV6::new(
                self.addr,
                port,
                config::EXTERNAL_FLOWINFO,
                config::EXTERNAL_SCOPE_ID,
            )
        }
    }

    pub fn forward(external_ref: Arc<Mutex<External>>, port: Port) -> Result<()> {
        let internal = SocketAddrV4::new(config::INTERNAL, port);

        let addr = SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            port,
            config::EXTERNAL_FLOWINFO,
            config::EXTERNAL_SCOPE_ID,
        );
        let socket = UdpSocket::bind(addr)?;

        let mut buf = [0; config::MAX_PACKET_BYTES];

        loop {
            let (num, src) = socket.recv_from(&mut buf)?;
            let data = &mut buf[..num];

            let mut external = external_ref.try_lock()?;

            match src.ip() {
                IpAddr::V4(src) /* outgoing */ => {
                    if src != config::INTERNAL {
                        let expected = config::INTERNAL;
                        info!("invalid internal source IP address (expected {expected:#}, found {src:#})");
                        continue;
                    }

                    socket.send_to(&data, external.socket_addr(port))?;
                },
                IpAddr::V6(src) /* incoming */ => {
                    match external.is(src) {
                        Ok(()) => socket.send_to(&data, internal)?,
                        /*Err(Error::ExternalSourceInvalid) | Err(Error::ExternalSourceBlacklisted) => {
                            //let expected = external.addr();
                            //info!("invalid external source IP address (expected {expected:#}, found {src:#})");
                            continue;
                        },*/
                        Err(err) => return Err(err),
                    };
                },
            };
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let external = Arc::new(Mutex::new(proxy::External::new()?));

    for port in config::ports() {
        let external_ref = Arc::clone(&external);
        let _ = thread::spawn(move || {
            match proxy::forward(external_ref, port) {
                Ok(()) => error!(
                    "proxying of port {port} exited without an error, which should never happen"
                ),
                Err(err) => error!("proxying of port {port} exited with error: {err}"),
            };

            exit(1);
        });
    }

    loop {
        thread::sleep(Duration::MAX);
    }
}
