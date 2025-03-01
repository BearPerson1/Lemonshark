// Copyright(C) Facebook, Inc. and its affiliates.
// Copyright (c) BearPerson1
// Created: 2025-03-01 11:50:58 UTC
// SPDX-License-Identifier: Apache-2.0

use crate::error::NetworkError;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::SplitSink;
use futures::stream::StreamExt as _;
use log::{debug, info, warn};
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, TcpSocket};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use socket2::Socket;
use std::os::unix::io::{AsRawFd, FromRawFd};

#[cfg(test)]
#[path = "tests/receiver_tests.rs"]
pub mod receiver_tests;

// Constants for buffer sizes
const TCP_RECV_BUF_SIZE: u32 = 131072;  // 2MB receive buffer
const TCP_SEND_BUF_SIZE: u32 = 16384;  // 2MB send buffer

/// Convenient alias for the writer end of the TCP channel.
pub type Writer = SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>;

#[async_trait]
pub trait MessageHandler: Clone + Send + Sync + 'static {
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>>;
}

pub struct Receiver<Handler: MessageHandler> {
    address: SocketAddr,
    handler: Handler,
}

impl<Handler: MessageHandler> Receiver<Handler> {
    pub fn spawn(address: SocketAddr, handler: Handler) {
        tokio::spawn(async move {
            Self { address, handler }.run().await;
        });
    }

    async fn run(&self) {
        // Create a TCP socket with optimized buffer settings
        let socket = match TcpSocket::new_v4() {
            Ok(socket) => {
                if let Err(e) = socket.set_recv_buffer_size(TCP_RECV_BUF_SIZE) {
                    warn!("Failed to set receive buffer size: {}", e);
                }
                if let Err(e) = socket.set_send_buffer_size(TCP_SEND_BUF_SIZE) {
                    warn!("Failed to set send buffer size: {}", e);
                }
                socket
            }
            Err(e) => {
                warn!("Failed to create TCP socket: {}", e);
                return;
            }
        };

        // Bind and listen
        if let Err(e) = socket.bind(self.address) {
            warn!("Failed to bind address {}: {}", self.address, e);
            return;
        }

        let listener = match socket.listen(1024) {
            Ok(l) => l,
            Err(e) => {
                warn!("Failed to listen on address {}: {}", self.address, e);
                return;
            }
        };

        debug!("Listening on {} with optimized buffers", self.address);
        debug!("Configured receive buffer size: {} bytes", TCP_RECV_BUF_SIZE);
        debug!("Configured send buffer size: {} bytes", TCP_SEND_BUF_SIZE);

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(e) => {
                    warn!("{}", NetworkError::FailedToListen(e));
                    continue;
                }
            };

            // Configure accepted socket
            if let Err(e) = socket.set_nodelay(true) {
                warn!("Failed to set TCP_NODELAY for {}: {}", peer, e);
            }

            info!("Incoming connection established with {}", peer);
            Self::spawn_runner(socket, peer, self.handler.clone()).await;
        }
    }

    async fn spawn_runner(socket: TcpStream, peer: SocketAddr, handler: Handler) {
        tokio::spawn(async move {
            // Get the socket2::Socket to check buffer sizes
            let socket2 = unsafe { Socket::from_raw_fd(socket.as_raw_fd()) };
            if let Ok(size) = socket2.recv_buffer_size() {
                debug!("Actual receive buffer size for {}: {} bytes", peer, size);
            }
            if let Ok(size) = socket2.send_buffer_size() {
                debug!("Actual send buffer size for {}: {} bytes", peer, size);
            }
            // Don't close the socket2 as it would close our TcpStream
            std::mem::forget(socket2);

            let transport = Framed::new(socket, LengthDelimitedCodec::new());
            let (mut writer, mut reader) = transport.split();
            while let Some(frame) = reader.next().await {
                match frame.map_err(|e| NetworkError::FailedToReceiveMessage(peer, e)) {
                    Ok(message) => {
                        if let Err(e) = handler.dispatch(&mut writer, message.freeze()).await {
                            warn!("{}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                        return;
                    }
                }
            }
            warn!("Connection closed by peer {}", peer);
        });
    }
}