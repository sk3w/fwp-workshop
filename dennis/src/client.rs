use std::{io, net::SocketAddr};

use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use crate::{DnsCodec, Message};

pub struct Client {
    framed: UdpFramed<DnsCodec, UdpSocket>,
    server_addr: SocketAddr,
}

impl Client {
    pub async fn connect(server_addr: SocketAddr) -> io::Result<Self> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let framed = UdpFramed::new(udp_socket, DnsCodec);
        Ok(Self { framed, server_addr })
    }

    pub async fn send_query(&mut self, message: Message) -> io::Result<Message> {
        self.framed.send((message, self.server_addr)).await?;
        let (response, _) = self.framed.next().await.unwrap()?;
        Ok(response)
    }
}
