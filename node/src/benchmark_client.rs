// Copyright(C) Facebook, Inc. and its affiliates.
// Copyright (c) 2025, BearPerson1
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use bytes::BufMut as _;
use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::{info, warn, debug};
use rand::Rng;
use tokio::time::error::Elapsed;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use std::sync::{Arc, Mutex};

//lemonshark
use network::receiver::{Receiver, MessageHandler, Writer};
use network::reliable_sender::{ReliableSender};  
use async_trait::async_trait;
use bytes::Bytes;
use std::error::Error;
use primary::ClientMessage;
use primary::messages::{Header, Certificate};
use std::collections::{HashMap,HashSet};

#[derive(Clone)]
struct ClientMessageHandler {
    tx_chain: tokio::sync::mpsc::Sender<ChainMessage>,
    last_causal_chain_counter: Arc<Mutex<u64>>,
    confirmed_depth: Arc<Mutex<u64>>,
    buffer_spec_headers: Arc<Mutex<HashMap<u64,Header>>>, 
    buffer_certs: Arc<Mutex<HashMap<u64,Header>>>, 
    purged_headers:Arc<Mutex<HashSet<Header>>>, 
    longest_causal_chain: u64,
}

#[derive(Clone)]
struct ChainMessage {
    should_send: bool,
    counter: u64,
}

impl ClientMessageHandler {
    fn new(
        tx_chain: tokio::sync::mpsc::Sender<ChainMessage>,
        confirmed_depth: u64,
        longest_causal_chain: u64,
        ) -> Self {
        Self {
            tx_chain,
            last_causal_chain_counter: Arc::new(Mutex::new(1)),
            confirmed_depth: Arc::new(Mutex::new(confirmed_depth)),
            buffer_spec_headers: Arc::new(Mutex::new(HashMap::new())), 
            buffer_certs: Arc::new(Mutex::new(HashMap::new())),
            purged_headers:  Arc::new(Mutex::new(HashSet::new())),
            longest_causal_chain,
        }
    }

    async fn process_primary_message(&self, msg: &ClientMessage) -> Result<ChainMessage, Box<dyn Error>> {
        match msg.message_type {
            0 => {
                // Header
                debug!("Processing Header message from round {}", msg.header.round);
                let mut purged = self.purged_headers.lock().unwrap();
                let mut confirmed = self.confirmed_depth.lock().unwrap();
                let mut counter = self.last_causal_chain_counter.lock().unwrap();
                let mut headers = self.buffer_spec_headers.lock().unwrap();
                let mut certs = self.buffer_certs.lock().unwrap();
                let mut should_send = true;

                if msg.header.causal_transaction_id == *counter {
                    *counter = *counter + 1;
                    headers.insert(msg.header.causal_transaction_id,msg.header.clone());
                }
                if *counter > self.longest_causal_chain {
                    should_send = false;
                }
                debug!("Final state - Confirmed depth: {}, Headers buffered: {}, Certificates buffered: {}, Purged: {}", 
                 *confirmed, headers.len(), certs.len(), purged.len());

                Ok(ChainMessage {
                    should_send,
                    counter:*counter,
                })
            },
            1 => {
                // Certificate
                debug!("Processing Certificate message from round {}", msg.header.round);

                let mut purged = self.purged_headers.lock().unwrap();
                let mut confirmed = self.confirmed_depth.lock().unwrap();
                let mut counter = self.last_causal_chain_counter.lock().unwrap();
                let mut headers = self.buffer_spec_headers.lock().unwrap();
                let mut certs = self.buffer_certs.lock().unwrap();
                let mut restart = false;
                let mut should_send = false;

                if purged.iter().any(|h| {
                    h.round == msg.header.round && 
                    h.causal_transaction_id == msg.header.causal_transaction_id &&
                    h.shard_num == msg.header.shard_num
                }) {
                    debug!("Certificate header was previously purged, ignoring");
                    return Ok(ChainMessage {
                        should_send: false,
                        counter: *counter,
                    });
                }
  // Check if this certificate corresponds to a header we're waiting for
                if headers.contains_key(&msg.header.causal_transaction_id) {
                    if let Some(min_id) = headers.keys().min() {
                         // Check if this is the smallest transaction ID in headers
                        debug!("Current minimum transaction ID in headers: {}", min_id);
                        if msg.header.causal_transaction_id == *min_id {
                            debug!("Processing minimum transaction ID certificate");
                            if !msg.header.collision_fail {
                                debug!("No collision detected, incrementing confirmed depth to {}", *confirmed + 1);

                                *confirmed += 1;
                                 //NOTE: for performance check
                                info!("Finalizing causal-transaction {}",confirmed);
                                 // Remove the processed header and add to purged
                                if let Some(header) = headers.remove(&msg.header.causal_transaction_id) {
                                    purged.insert(header.clone());
                                }
                                debug!("Removed header for transaction ID {}", msg.header.causal_transaction_id);
                                 // Recursively process any buffered certificates
                                let mut next_id = msg.header.causal_transaction_id + 1;
                                debug!("Checking for chained certificates starting from ID {}", next_id);
                                while let Some(next_cert) = certs.remove(&next_id) {
                                    debug!("Found buffered certificate for ID {}", next_id);
                                    if headers.contains_key(&next_id) {
                                        if !next_cert.collision_fail {
                                            debug!("Processing chained certificate {}, incrementing confirmed depth", next_id);

                                            *confirmed += 1;
                                              //NOTE: for performance check
                                            info!("Finalizing causal-transaction {}",confirmed);

                                            if let Some(header) = headers.remove(&next_id) {
                                                purged.insert(header.clone());
                                            }
                                            next_id += 1;
                                        } else {
                                            debug!("Collision detected in chained certificate {}, purging buffers", next_id);
                                            *confirmed+=1;
                                              //NOTE: for performance check
                                            info!("Finalizing causal-transaction {}",confirmed);
                                            for header in headers.values() {
                                                purged.insert(header.clone());
                                            }
                                            headers.clear();
                                            certs.clear();
                                            restart = true;
                                            break;
                                        }
                                    } else {
                                        debug!("No matching header found for certificate {}, stopping chain processing", next_id);
                                        break;
                                    }
                                }
                            } else {
                                debug!("Collision detected in minimum ID certificate, purging buffers");
                                *confirmed += 1;
                                info!("Finalizing causal-transaction {}",confirmed);
                                for header in headers.values() {
                                    purged.insert(header.clone());
                                }
                                headers.clear();
                                certs.clear();
                                restart = true;
                            }
                        } else {
                            debug!("Certificate {} is not the minimum ({}), buffering for later",
                                   msg.header.causal_transaction_id, min_id);
                            certs.insert(msg.header.causal_transaction_id, msg.header.clone());
                            should_send = false;
                        }
                    }
                } else {
                    debug!("No matching header found for certificate {}, ignoring", msg.header.causal_transaction_id);
                    should_send = false;
                }

                if restart {
                    if *confirmed == self.longest_causal_chain {
                        should_send = false;
                    } else {
                        *counter = *confirmed + 1;
                        should_send = true;
                    }
                }
                
                debug!("Final state - Confirmed depth: {}, Headers buffered: {}, Certificates buffered: {}, Purged: {}", 
                       *confirmed, headers.len(), certs.len(), purged.len());

                debug!("counter: {}, confirmed: {}", counter, confirmed);

                Ok(ChainMessage {
                    should_send,
                    counter: *counter,
                })
            },
            _ => {
                warn!("Unknown message type: {}", msg.message_type);
                Ok(ChainMessage {
                    should_send: false,
                    counter: 0,
                })
            }
        }
    }
}

#[async_trait]
impl MessageHandler for ClientMessageHandler {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        match bincode::deserialize::<ClientMessage>(&message) {
            Ok(msg) => {
                debug!("Received Message:");
                debug!("├─ Message Type: {}", if msg.message_type == 0 { "Header" } else { "Certificate" });
                debug!("├─ Round: {}", msg.header.round);
                debug!("├─ Collision fail? {} ",msg.header.collision_fail);
                debug!("├─ Causal txn id: {}",msg.header.causal_transaction_id);
                debug!("├─ Shard: {}", msg.header.shard_num);
                
                let send_next_check = self.process_primary_message(&msg).await?;
                if send_next_check.should_send {
                    if let Err(e) = self.tx_chain.send(send_next_check.clone()).await {
                        warn!("Failed to request new causal chain transaction: {}", e);
                    }
                }
                Ok(())
            }
            Err(e) => {
                log::error!("Deserialization error: {}", e);
                log::error!("First 4 bytes: {:?}", &message.get(..4).unwrap_or(&[]));
                log::error!("Message length: {}", message.len());
                Ok(())
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Narwhal and Tusk.")
        .args_from_usage("<ADDR> 'The network address of the node where to send txs'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The rate (txs/s) at which to send the transactions'")
        .args_from_usage("--nodes=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'")
        .args_from_usage("--longest_causal_chain=<INT> 'The longest causal chain value'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .args_from_usage("--primary-client-port=[PORT] 'Port for primary-to-client communication'")
        .get_matches();

    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format_timestamp_millis()
        .init();

    let target = matches
        .value_of("ADDR")
        .unwrap()
        .parse::<SocketAddr>()
        .context("Invalid socket address format")?;
    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let nodes = matches
        .values_of("nodes")
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;
    let longest_causal_chain = matches
        .value_of("longest_causal_chain")
        .unwrap()
        .parse::<u64>()
        .context("The longest_causal_chain must be a non-negative integer")?;
    
    info!("Node address: {}", target);
    info!("Transactions size: {} B", size);
    info!("Transactions rate: {} tx/s", rate);

    let primary_port = matches
        .value_of("primary-client-port")
        .map(|p| p.parse::<u16>())
        .transpose()
        .context("Invalid primary client port")?;

    let target_ip = target.ip();
    let primary_to_client_addr = SocketAddr::new(
        "0.0.0.0".parse().unwrap(),
        primary_port.unwrap()
    );
    
    debug!("Primary to client address: {}", primary_to_client_addr);

    let client = Client {
        target,
        size,
        rate,
        nodes,
        longest_causal_chain,
        primary_to_client_addr,
    };

    client.wait().await;
    client.send().await.context("Failed to submit transactions")
}

struct Client {
    target: SocketAddr,
    size: usize,
    rate: u64,
    nodes: Vec<SocketAddr>,
    longest_causal_chain: u64,
    primary_to_client_addr: SocketAddr,
}

impl Client {
    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 20;
        const BURST_DURATION: u64 = 1000 / PRECISION;
        info!("longest_causal_chain: {}", self.longest_causal_chain);

        // Initialize ReliableSender with custom timeouts
        let mut sender = ReliableSender::new();
        let mut causal_sender = ReliableSender::new();

        let mut causal_handle = None;

        if self.longest_causal_chain != 0 {
            let (tx_chain, mut rx_chain) = tokio::sync::mpsc::channel::<ChainMessage>(100);
            let handler = ClientMessageHandler::new(
                tx_chain,
                0,
                self.longest_causal_chain,
            );
            Receiver::spawn(self.primary_to_client_addr, handler);

            let size = self.size;
            let longest_causal_chain = self.longest_causal_chain;
            let target = self.target;



        causal_handle = Some(tokio::spawn(async move {
            // Send initial causal chain transaction if enabled
            let mut tx = BytesMut::with_capacity(size);
            if longest_causal_chain != 0 {
                tx.clear();
                tx.put_u8(2u8);
                tx.put_u64(1);
                tx.resize(size, 0u8);
                let bytes = tx.split().freeze();
                
                let cancel_handler = causal_sender.send(target, bytes).await;
                match cancel_handler.await {
                    Ok(_) => info!("Sent and confirmed causal-transaction {}", 1),
                    Err(e) => warn!("Failed to confirm causal-transaction {}: {:?}", 1, e),
                }
                info!("Sending causal-transaction {}", 1);

                while let Some(chain_message) = rx_chain.recv().await {
                    if chain_message.should_send && longest_causal_chain != 0 {
                        tx.clear();
                        tx.put_u8(2u8);
                        tx.put_u64(chain_message.counter);
                        tx.resize(size, 0u8);
                        let bytes = tx.split().freeze();
                        
                        let cancel_handler = causal_sender.send(target, bytes).await;
                        match cancel_handler.await {
                            Ok(_) => info!("Sent and confirmed causal-transaction {}", chain_message.counter),
                            Err(e) => warn!("Failed to confirm causal-transaction {}: {:?}", chain_message.counter, e),
                        }
                        info!("Sending causal-transaction {}", chain_message.counter);
                    }
                }
            }
        }));
        }

        if self.size < 9 {
        return Err(anyhow::Error::msg(
            "Transaction size must be at least 9 bytes",
        ));
        }

        let burst = self.rate / PRECISION;
        let mut tx = BytesMut::with_capacity(self.size);
        let mut counter = 0;
        let mut r = rand::thread_rng().gen();
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        debug!("Start sending transactions");

        'main: loop {
        interval.as_mut().tick().await;
        let now = Instant::now();

        for x in 0..burst {
            if x == counter % burst {
                info!("Sending sample transaction {}", counter);
                tx.put_u8(0u8);
                tx.put_u64(counter);
            } else {
                r += 1;
                tx.put_u8(1u8);
                tx.put_u64(r);
            };

            tx.resize(self.size, 0u8);
            let bytes = tx.split().freeze();

            // Use ReliableSender for regular transactions
            let cancel_handler = sender.send(self.target, bytes).await;
            tokio::spawn(async move {
                if let Err(e) = cancel_handler.await {
                    warn!("Transaction confirmation failed: {:?}", e);
                }
            });
        }

        if now.elapsed().as_millis() > BURST_DURATION as u128 {
            warn!("Transaction rate too high for this client");
        }
        counter += 1;
        }

        // Clean up the causal chain task
        if let Some(handle) = causal_handle {
        handle.abort();
        match handle.await {
            Ok(_) => debug!("Causal chain task cleaned up successfully"),
            Err(e) => warn!("Causal chain task cleanup error: {:?}", e),
        }
        }

        Ok(())
        }

        pub async fn wait(&self) {
        info!("Waiting for all nodes to be online...");
        join_all(self.nodes.iter().cloned().map(|address| {
        tokio::spawn(async move {
            while TcpStream::connect(address).await.is_err() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        }))
        .await;
        }
        }