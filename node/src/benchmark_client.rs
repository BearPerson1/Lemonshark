// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use bytes::BufMut as _;
use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::{info, warn, debug};
use rand::Rng;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use std::sync::{Arc, Mutex};

//lemonshark
use network::receiver::{Receiver, MessageHandler, Writer};
use async_trait::async_trait;
use bytes::Bytes;
use std::error::Error;
use primary::ClientMessage;
use primary::messages::{Header, Certificate};

#[derive(Clone)]
struct ClientMessageHandler {
    tx_chain: tokio::sync::mpsc::Sender<ChainMessage>,
    last_causal_chain_counter: Arc<Mutex<u64>>,
}

#[derive(Clone)]
struct ChainMessage {
    should_send: bool,
    counter: u64,
}

impl ClientMessageHandler {
    fn new(tx_chain: tokio::sync::mpsc::Sender<ChainMessage>) -> Self {
        Self {
            tx_chain,
            last_causal_chain_counter: Arc::new(Mutex::new(1)),
        }
    }

    async fn process_primary_message(&self, msg: &ClientMessage) -> Result<ChainMessage, Box<dyn Error>> {
        let counter = {
            let mut counter = self.last_causal_chain_counter.lock().unwrap();
            *counter += 1;
            *counter
        };
        
        // Set should_send based on counter value
        let should_send = if counter > 2 {
            false
        } else {
            true
        };
    
        Ok(ChainMessage {
            should_send,
            counter,
        })
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
                debug!("├─ Shard: {}", msg.header.shard_num);
                debug!("├─ Author: {}", msg.header.author);
                debug!("├─ Parent Shards: {:?}", msg.header.parents_id_shard);
                debug!("└─ Payload Size: {} bytes", msg.header.payload.len());
                
                // lemonshark:
                let send_next_check = self.process_primary_message(&msg).await?;
                if send_next_check.should_send {
                    if let Err(e) = self.tx_chain.send(send_next_check).await {
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

    // NOTE: This log entry is used to compute performance.
    info!("Transactions size: {} B", size);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions rate: {} tx/s", rate);

    let primary_port = matches
    .value_of("primary-client-port")
    .map(|p| p.parse::<u16>())
    .transpose()
    .context("Invalid primary client port")?;

    let target_ip = target.ip();
    
    let primary_to_client_addr = SocketAddr::new(
        target_ip,
        primary_port.unwrap_or_else(|| target.port() -2 )
    );

    let client = Client {
        target,
        size,
        rate,
        nodes,
        longest_causal_chain,
        // Lemonshark: this is the address the client should listen too messages on
        primary_to_client_addr,
    };

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
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
        const PRECISION: u64 = 20; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // Create channel for receiving signals from the message handler
        let (tx_chain, mut rx_chain) = tokio::sync::mpsc::channel::<ChainMessage>(100);
        let handler = ClientMessageHandler::new(tx_chain);
        Receiver::spawn(self.primary_to_client_addr, handler);


        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }
        // Lemonshark
        debug!("longest_causal_chain: {}",self.longest_causal_chain);   

        // Connect to the mempool.
        let stream = TcpStream::connect(self.target)
            .await
            .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        let burst = self.rate / PRECISION;
        let mut tx = BytesMut::with_capacity(self.size);
        let mut counter = 0;
        let mut r = rand::thread_rng().gen();
        let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);


        // lemonshark: Send initial causal chain transaction if enabled
        if self.longest_causal_chain != 0 {
            tx.clear();
            tx.put_u8(2u8); // Special transaction type
            tx.put_u64(1);
            tx.resize(self.size, 0u8);
            let bytes = tx.split().freeze();
            transport.send(bytes).await?;
            debug!("Sent initial causal chain transaction");
        }

        // NOTE: This log entry is used to compute performance.
        debug!("Start sending transactions");

        'main: loop {
            // Lemonshark: Check for message from handler about sending new causal chain transaction

            if let Ok(chain_message) = rx_chain.try_recv() {
                if chain_message.should_send && self.longest_causal_chain != 0 {
                    tx.clear();
                    tx.put_u8(2u8);
                    tx.put_u64(chain_message.counter);
                    tx.resize(self.size, 0u8);
                    let bytes = tx.split().freeze();
                    if let Err(e) = transport.send(bytes).await {
                        warn!("Failed to send causal chain transaction: {}", e);
                        break 'main;
                    }
                    debug!("Sent causal chain transaction {}", chain_message.counter);
                    continue;
                }
            }

            interval.as_mut().tick().await;
            let now = Instant::now();

            for x in 0..burst {
                if x == counter % burst {
                    // NOTE: This log entry is used to compute performance.
                    info!("Sending sample transaction {}", counter);

                    tx.put_u8(0u8); // Sample txs start with 0.
                    tx.put_u64(counter); // This counter identifies the tx.
                } else {
                    r += 1;
                    tx.put_u8(1u8); // Standard txs start with 1.
                    tx.put_u64(r); // Ensures all clients send different txs.
                };

                tx.resize(self.size, 0u8);
                let bytes = tx.split().freeze();
                if let Err(e) = transport.send(bytes).await {
                    warn!("Failed to send transaction: {}", e);
                    break 'main;
                }
            }
            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
                warn!("Transaction rate too high for this client");
            }
            counter += 1;
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
