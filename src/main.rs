use std::io;
use std::iter::Chain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::ops::RangeInclusive;
use std::process::exit;
use std::sync::{Arc, RwLock};
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

    #[error("no DNS record for external server hostname")]
    NoAddrToHostname,

    #[error("failed to lock mutex")]
    LockMutex,
}

type Result<T> = std::result::Result<T, Error>;

mod config {
    use super::*;

    pub const MAX_PACKET_BYTES: usize = 1500;

    pub const INTERNAL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 128, 40, 252));
    pub const EXTERNAL: &str = "06028.sip.arcor.de";

    pub const EXTERNAL_SCOPE_ID: u32 = 0;

    pub const RESOLVE_INTERVAL: Duration = Duration::from_secs(60);
    pub const NAMESERVER: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
        53,
        0,
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
    use hickory_resolver::config::{
        LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
    };
    use hickory_resolver::Resolver;

    pub fn resolve() -> Result<IpAddr> {
        let hostname = config::EXTERNAL;

        let mut cfg = ResolverConfig::new();
        cfg.add_name_server(NameServerConfig::new(config::NAMESERVER, Protocol::Udp));

        let mut opts = ResolverOpts::default();
        opts.ip_strategy = LookupIpStrategy::Ipv6thenIpv4;

        let resolver = Resolver::new(cfg, opts)?;
        let response = resolver.lookup_ip(hostname)?;

        match response.iter().next() {
            Some(ip_addr) => Ok(ip_addr),
            None => Err(Error::NoAddrToHostname),
        }
    }

    pub fn resolve_regular(external: Arc<RwLock<proxy::External>>) -> Result<()> {
        loop {
            thread::sleep(config::RESOLVE_INTERVAL);
            external
                .try_write()
                .map_err(|_| Error::LockMutex)?
                .resolve()?;
        }
    }
}

mod proxy {
    use super::*;

    pub struct External {
        addr: IpAddr,
    }

    impl External {
        pub fn new() -> Result<External> {
            Ok(External {
                addr: dns::resolve()?,
            })
        }

        pub fn resolve(&mut self) -> Result<()> {
            self.addr = dns::resolve()?;

            Ok(())
        }

        pub fn socket_addr(&self, port: Port) -> SocketAddr {
            SocketAddr::new(self.addr, port)
        }
    }

    pub fn forward(external: Arc<RwLock<External>>, port: Port) -> Result<()> {
        let internal = SocketAddr::new(config::INTERNAL, port);

        let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, config::EXTERNAL_SCOPE_ID);
        let socket = UdpSocket::bind(addr)?;

        let mut buf = [0; config::MAX_PACKET_BYTES];

        loop {
            let (num, src) = socket.recv_from(&mut buf)?;
            let data = &mut buf[..num];

            if src == internal {
                socket.send_to(
                    data,
                    external
                        .try_read()
                        .map_err(|_| Error::LockMutex)?
                        .socket_addr(port),
                )?;
            } else {
                socket.send_to(data, internal)?;
            }
        }
    }
}

fn main() -> Result<()> {
    let external = Arc::new(RwLock::new(proxy::External::new()?));

    for port in config::ports() {
        let external_ref = Arc::clone(&external);
        let _ = thread::spawn(move || {
            match proxy::forward(external_ref, port) {
                Ok(()) => unreachable!(),
                Err(err) => eprintln!("proxying of port {port} exited with error: {err}"),
            };

            exit(1);
        });
    }

    let _ = thread::spawn(move || {
        match dns::resolve_regular(Arc::clone(&external)) {
            Ok(()) => unreachable!(),
            Err(err) => eprintln!("regular DNS resolve of external host exited with error: {err}"),
        };

        exit(1);
    });

    loop {
        thread::sleep(Duration::MAX);
    }
}
