// Copyright(C) Facebook, Inc. and its affiliates.
use crate::quorum_waiter::QuorumWaiterMessage;
use crate::worker::WorkerMessage;
use log::{info,debug};
use bytes::Bytes;
#[cfg(feature = "benchmark")]
use crypto::Digest;
use crypto::PublicKey;
#[cfg(feature = "benchmark")]
use ed25519_dalek::{Digest as _, Sha512};


use network::ReliableSender;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/batch_maker_tests.rs"]
pub mod batch_maker_tests;

pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;

/// Assemble clients transactions into batches.
pub struct BatchMaker {
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch (in ms).
    max_batch_delay: u64,
    /// Channel to receive transactions from the network.
    rx_transaction: Receiver<Transaction>,
    /// Output channel to deliver sealed batches to the `QuorumWaiter`.
    tx_message: Sender<QuorumWaiterMessage>,
    /// The network addresses of the other workers that share our worker id.
    workers_addresses: Vec<(PublicKey, SocketAddr)>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
    /// A network sender to broadcast the batches to the other workers.
    network: ReliableSender,
}

impl BatchMaker {
    pub fn spawn(
        batch_size: usize,
        max_batch_delay: u64,
        rx_transaction: Receiver<Transaction>,
        tx_message: Sender<QuorumWaiterMessage>,
        workers_addresses: Vec<(PublicKey, SocketAddr)>,
    ) {
        tokio::spawn(async move {
            Self {
                batch_size,
                max_batch_delay,
                rx_transaction,
                tx_message,
                workers_addresses,
                current_batch: Batch::with_capacity(batch_size * 2),
                current_batch_size: 0,
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    /// Main loop receiving incoming transactions and creating batches.
    async fn run(&mut self) {
        let timer = sleep(Duration::from_millis(self.max_batch_delay));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {
                    self.current_batch_size += transaction.len();
                    self.current_batch.push(transaction);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                    }
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.is_empty() {
                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal and broadcast the current batch.
    async fn seal(&mut self) {
        #[cfg(feature = "benchmark")]
        let size = self.current_batch_size;

        // Look for sample txs (they all start with 0) and gather their txs id (the next 8 bytes).

        // lemonshark: also 2: our special causal transactions
        #[cfg(feature = "benchmark")]
        let tx_ids: Vec<(u8, u64)> = self
            .current_batch
            .iter()
            .filter(|tx| (tx[0] == 0u8 || tx[0] == 2u8) && tx.len() > 8)
            .filter_map(|tx| {
                tx[1..9].try_into()
                    .ok()
                    .map(|bytes| (tx[0], u64::from_be_bytes(bytes)))
            })
            .collect();

        // todo: delete
        // debug!("Found {} total transactions, {} special transactions", 
        // tx_ids.len(),
        // tx_ids.iter().filter(|(tx_type, _)| *tx_type == 2).count()
        // );
    
        // Get the special transaction ID if there is one
        let special_txn_id = tx_ids.iter()
        .find(|(tx_type, _)| *tx_type == 2)
        .map(|(_, id)| *id);
        // Serialize the batch.
        self.current_batch_size = 0;
        let batch: Vec<_> = self.current_batch.drain(..).collect();

        // todo: delete
        // debug!("=== Batch Sending Details ===");
        // debug!("Number of transactions: {}", batch.len());
        // debug!("Special transaction ID: {:?}", special_txn_id);
        // debug!("Worker addresses count: {}", self.workers_addresses.len());
        // debug!("Current batch size before clearing: {}", self.current_batch_size);


        let message = WorkerMessage::Batch(batch, special_txn_id);
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own batch");
    
        

        #[cfg(feature = "benchmark")]
        {
            // NOTE: This is one extra hash that is only needed to print the following log entries.
            let digest = Digest(
                Sha512::digest(&serialized).as_slice()[..32]
                    .try_into()
                    .unwrap(),
            );
    
            for (tx_type, id) in tx_ids {
                // NOTE: This log entry is used to compute performance.
                match tx_type {
                    0 => info!(
                        "Batch {:?} contains sample tx {}",
                        digest,
                        id
                    ),
                    2 => info!(
                        "Batch {:?} contains causal-chain tx {}",
                        digest,
                        id
                    ),
                    _ => {} // Should never happen due to the filter above
                }
            }
    
            // NOTE: This log entry is used to compute performance.
            info!("Batch {:?} contains {} B", digest, size);
        }

        // Broadcast the batch through the network.
        let (names, addresses): (Vec<_>, _) = self.workers_addresses.iter().cloned().unzip();
        let bytes = Bytes::from(serialized.clone());
        let handlers = self.network.broadcast(addresses, bytes).await;
        
        debug!("[BatchMaker] Sending batch to QuorumWaiter");
        if let Ok(worker_message) = bincode::deserialize::<WorkerMessage>(&serialized) {
            match worker_message {
                WorkerMessage::Batch(_, special_txn_id) => {
                    debug!("[BatchMaker] Batch contains special_txn_id: {:?}", special_txn_id);
                },
                _ => debug!("[BatchMaker] Non-batch message being sent"),
            }
        }

        

        // Send the batch through the deliver channel for further processing.
        self.tx_message
            .send(QuorumWaiterMessage {
                batch: serialized,
                handlers: names.into_iter().zip(handlers.into_iter()).collect(),
            })
            .await
            .expect("Failed to deliver batch");
    }
}
