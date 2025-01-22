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


//lemonshark
use network::receiver::{Receiver, MessageHandler, Writer};
use async_trait::async_trait;
use bytes::Bytes;
use std::error::Error;
use primary::ClientMessage; // Add this import
use primary::messages::{Header, Certificate};

#[derive(Clone)]
struct ClientMessageHandler;


#[async_trait]
impl MessageHandler for ClientMessageHandler {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        // Try Header first
        match bincode::deserialize::<Header>(&message) {
            Ok(header) => {
                info!("Received Header Message");
                info!("├─ Message Type: Header");
                info!("│  ├─ Round: {}", header.round);
                info!("│  ├─ Shard: {}", header.shard_num);
                info!("│  ├─ Author: {}", header.author);
                info!("│  ├─ Parent Shards: {:?}", header.parents_id_shard);
                info!("│  └─ Payload Size: {} bytes", header.payload.len());
                return Ok(());
            }
            Err(_) => {
                // If Header fails, try Certificate
                match bincode::deserialize::<Certificate>(&message) {
                    Ok(cert) => {
                        info!("Received Certificate Message");
                        info!("├─ Message Type: Certificate");
                        info!("│  ├─ Round: {}", cert.header.round);
                        info!("│  ├─ Shard: {}", cert.header.shard_num);
                        info!("│  ├─ Author: {}", cert.header.author);
                        info!("│  ├─ Parent Shards: {:?}", cert.header.parents_id_shard);
                        info!("│  └─ Votes: {}", cert.votes.len());
                        return Ok(());
                    }
                    Err(e) => {
                        log::error!("├─ Deserialization Error");
                        log::error!("│  └─ {}", e);
                    }
                }
            }
        }
        Ok(())
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

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
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

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }
        info!("longest_causal_chain: {}",self.longest_causal_chain);

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

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        'main: loop {
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

    fn start_receiver(&self) {
        let handler = ClientMessageHandler;
        // Using the pre-defined primary_to_client_addr
        Receiver::spawn(self.primary_to_client_addr, handler);
        debug!("Started receiver on {}", self.primary_to_client_addr);
    }

    pub async fn wait(&self) {
        self.start_receiver();

        // Wait for all nodes to be online.
        
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
