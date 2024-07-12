use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6, UdpSocket};
use std::ops::RangeInclusive;
use std::process::exit;
use std::thread;

mod config {
    use super::*;

    pub const INTERNAL: Ipv4Addr = Ipv4Addr::new(10, 128, 40, 252);
    pub const EXTERNAL: &str = "06028.sip.arcor.de";

    pub const SIP_PORTS: RangeInclusive<u16> = 5060..=5080;
    pub const RTP_PORTS: RangeInclusive<u16> = 16384..=16482;
}

mod proxy {
    use super::*;

    pub fn forward(port: u16) -> std::io::Result<()> {
        let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        let socket = UdpSocket::bind(addr)?;

        Ok(())
    }
}

fn main() -> std::io::Result<()> {
    for port in config::SIP_PORTS.chain(config::RTP_PORTS) {
        let _ = thread::spawn(move || {
            proxy::forward(port);
            exit(1);
        });
    }

    Ok(())
}
