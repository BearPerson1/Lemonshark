// Copyright(C) Facebook, Inc. and its affiliates.
// Copyright (c) BearPerson1
// Created: 2025-03-01 12:06:12 UTC
// SPDX-License-Identifier: Apache-2.0

use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{debug, info, warn};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use socket2::Socket;
use std::os::unix::io::{AsRawFd, FromRawFd};

#[cfg(test)]
#[path = "tests/reliable_sender_tests.rs"]
pub mod reliable_sender_tests;

// Constants for buffer sizes
const TCP_SEND_BUF_SIZE: u32 =  1000_000;  // 2MB send buffer
const TCP_RECV_BUF_SIZE: u32 =  1000_000;  // 2MB receive buffer for ACKs
const CHANNEL_BUFFER_SIZE: usize = 1_000;   // Internal channel buffer size

/// Convenient alias for cancel handlers returned to the caller task.
pub type CancelHandler = oneshot::Receiver<Bytes>;

/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
/// This sender is 'reliable' in the sense that it keeps trying to re-transmit messages for which it didn't
/// receive an ACK back (until they succeed or are canceled).
pub struct ReliableSender {
    connections: HashMap<SocketAddr, Sender<InnerMessage>>,
    rng: SmallRng,
}

impl std::default::Default for ReliableSender {
    fn default() -> Self {
        Self::new()
    }
}

impl ReliableSender {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            rng: SmallRng::from_entropy(),
        }
    }

    fn spawn_connection(address: SocketAddr) -> Sender<InnerMessage> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);
        Connection::spawn(address, rx);
        tx
    }

    pub async fn send(&mut self, address: SocketAddr, data: Bytes) -> CancelHandler {
        let (sender, receiver) = oneshot::channel();
        self.connections
            .entry(address)
            .or_insert_with(|| Self::spawn_connection(address))
            .send(InnerMessage {
                data,
                cancel_handler: sender,
            })
            .await
            .expect("Failed to send internal message");
        receiver
    }

    pub async fn broadcast(
        &mut self,
        addresses: Vec<SocketAddr>,
        data: Bytes,
    ) -> Vec<CancelHandler> {
        let mut handlers = Vec::new();
        for address in addresses {
            let handler = self.send(address, data.clone()).await;
            handlers.push(handler);
        }
        handlers
    }

    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) -> Vec<CancelHandler> {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data).await
    }
}

#[derive(Debug)]
struct InnerMessage {
    data: Bytes,
    cancel_handler: oneshot::Sender<Bytes>,
}

struct Connection {
    address: SocketAddr,
    receiver: Receiver<InnerMessage>,
    retry_delay: u64,
    buffer: VecDeque<(Bytes, oneshot::Sender<Bytes>)>,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<InnerMessage>) {
        tokio::spawn(async move {
            Self {
                address,
                receiver,
                retry_delay: 200,
                buffer: VecDeque::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        let mut delay = self.retry_delay;
        let mut retry = 0;
        loop {
            // Create a TCP socket with optimized buffer settings
            let socket = match TcpSocket::new_v4() {
                Ok(socket) => {
                    if let Err(e) = socket.set_send_buffer_size(TCP_SEND_BUF_SIZE) {
                        warn!("Failed to set send buffer size: {}", e);
                    }
                    if let Err(e) = socket.set_recv_buffer_size(TCP_RECV_BUF_SIZE) {
                        warn!("Failed to set receive buffer size: {}", e);
                    }
                    socket
                }
                Err(e) => {
                    warn!("Failed to create TCP socket: {}", e);
                    continue;
                }
            };

            match socket.connect(self.address).await {
                Ok(stream) => {
                    info!("Outgoing connection established with {}", self.address);

                    // Log buffer sizes
                    let socket2 = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };
                    if let Ok(size) = socket2.send_buffer_size() {
                        debug!("Actual send buffer size for {}: {} bytes", self.address, size);
                    }
                    if let Ok(size) = socket2.recv_buffer_size() {
                        debug!("Actual receive buffer size for {}: {} bytes", self.address, size);
                    }
                    std::mem::forget(socket2);

                    // Reset the delay
                    delay = self.retry_delay;
                    retry = 0;

                    // Set TCP_NODELAY
                    if let Err(e) = stream.set_nodelay(true) {
                        warn!("Failed to set TCP_NODELAY for {}: {}", self.address, e);
                    }

                    let error = self.keep_alive(stream).await;
                    warn!("{}", error);
                }
                Err(e) => {
                    warn!("{}", NetworkError::FailedToConnect(self.address, retry, e));
                    let timer = sleep(Duration::from_millis(delay));
                    tokio::pin!(timer);

                    'waiter: loop {
                        tokio::select! {
                            () = &mut timer => {
                                delay = min(2*delay, 60_000);
                                retry += 1;
                                break 'waiter;
                            },
                            Some(InnerMessage{data, cancel_handler}) = self.receiver.recv() => {
                                self.buffer.push_back((data, cancel_handler));
                                self.buffer.retain(|(_, handler)| !handler.is_closed());
                            }
                        }
                    }
                }
            }
        }
    }

    async fn keep_alive(&mut self, stream: TcpStream) -> NetworkError {
        let mut pending_replies = VecDeque::new();
        let (mut writer, mut reader) = Framed::new(stream, LengthDelimitedCodec::new()).split();

        let error = 'connection: loop {
            while let Some((data, handler)) = self.buffer.pop_front() {
                if handler.is_closed() {
                    continue;
                }

                match writer.send(data.clone()).await {
                    Ok(()) => {
                        pending_replies.push_back((data, handler));
                    }
                    Err(e) => {
                        self.buffer.push_front((data, handler));
                        break 'connection NetworkError::FailedToSendMessage(self.address, e);
                    }
                }
            }

            tokio::select! {
                Some(InnerMessage{data, cancel_handler}) = self.receiver.recv() => {
                    self.buffer.push_back((data, cancel_handler));
                },
                response = reader.next() => {
                    let (data, handler) = match pending_replies.pop_front() {
                        Some(message) => message,
                        None => break 'connection NetworkError::UnexpectedAck(self.address)
                    };
                    match response {
                        Some(Ok(bytes)) => {
                            let _ = handler.send(bytes.freeze());
                        },
                        _ => {
                            pending_replies.push_front((data, handler));
                            break 'connection NetworkError::FailedToReceiveAck(self.address);
                        }
                    }
                },
            }
        };

        while let Some(message) = pending_replies.pop_back() {
            self.buffer.push_front(message);
        }
        error
    }
}