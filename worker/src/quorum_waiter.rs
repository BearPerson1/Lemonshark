// Copyright(C) Facebook, Inc. and its affiliates.
use crate::processor::SerializedBatchMessage;
use config::{Committee, Stake};
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use network::CancelHandler;
use tokio::sync::mpsc::{Receiver, Sender};
use log::{info, debug, warn};
use ed25519_dalek::Sha512;
use ed25519_dalek::Digest as _;
use std::convert::TryInto;


#[cfg(test)]
#[path = "tests/quorum_waiter_tests.rs"]
pub mod quorum_waiter_tests;

#[derive(Debug)]
pub struct QuorumWaiterMessage {
    /// A serialized `WorkerMessage::Batch` message.
    pub batch: SerializedBatchMessage,
    /// The cancel handlers to receive the acknowledgements of our broadcast.
    pub handlers: Vec<(PublicKey, CancelHandler)>,
}

/// The QuorumWaiter waits for 2f authorities to acknowledge reception of a batch.
pub struct QuorumWaiter {
    /// The committee information.
    committee: Committee,
    /// The stake of this authority.
    stake: Stake,
    /// Input Channel to receive commands.
    rx_message: Receiver<QuorumWaiterMessage>,
    /// Channel to deliver batches for which we have enough acknowledgements.
    tx_batch: Sender<SerializedBatchMessage>,
}

impl QuorumWaiter {
    /// Spawn a new QuorumWaiter.
    pub fn spawn(
        committee: Committee,
        stake: Stake,
        rx_message: Receiver<QuorumWaiterMessage>,
        tx_batch: Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                stake,
                rx_message,
                tx_batch,
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }


    /// Main loop.
    async fn run(&mut self) {

        
        while let Some(QuorumWaiterMessage { batch, handlers }) = self.rx_message.recv().await {
            // Calculate batch digest
            let digest = {
                let hash = Sha512::digest(&batch);
                let digest_bytes: [u8; 32] = hash.as_slice()[..32].try_into()
                    .expect("Failed to create digest");
                format!("{:?}", crypto::Digest(digest_bytes))
            };

            // Process incoming batch
            if let Ok(worker_message) = bincode::deserialize::<crate::worker::WorkerMessage>(&batch) {
                match worker_message {
                    crate::worker::WorkerMessage::Batch(txs, special_txn_id) => {
                        debug!("\n=== QuorumWaiter Processing New Batch ===");
                        debug!("Batch digest: {}", digest);
                        debug!("Total transactions: {}", txs.len());
                        debug!("Batch size: {} bytes", batch.len());
                        debug!("Special transaction ID: {:?}", special_txn_id);
                        debug!("Expected quorum threshold: {}", self.committee.quorum_threshold());
                        debug!("Starting stake (self): {}", self.stake);
                        debug!("Handlers awaiting votes: {}", handlers.len());
                    },
                    _ => {
                        debug!("[QuorumWaiter] Received non-batch message");
                        continue;
                    }
                }
            } else {
                warn!("[QuorumWaiter] Failed to deserialize batch message");
                continue;
            }

            let mut wait_for_quorum: FuturesUnordered<_> = handlers
                .into_iter()
                .map(|(name, handler)| {
                    let stake = self.committee.stake(&name);
                    Self::waiter(handler, stake)
                })
                .collect();

            // Track votes and stakes
            let mut total_stake = self.stake;
            let mut votes_received = 0;
            
            debug!("\n=== Starting Vote Collection for Batch {} ===", digest);

            debug!("Initial stake: {}", total_stake);

            while let Some(stake) = wait_for_quorum.next().await {
                total_stake += stake;
                votes_received += 1;
                
                debug!("\nReceived vote {} for batch {}", votes_received, digest);

                debug!("Vote stake value: {}", stake);
                debug!("Current total stake: {}/{}", total_stake, self.committee.quorum_threshold());

                if total_stake >= self.committee.quorum_threshold() {
                    debug!("\n=== Quorum Reached for Batch {} ===", digest);

                    debug!("Final total stake: {}", total_stake);
                    debug!("Total votes received: {}", votes_received);

                    // Log special transaction details if present
                    if let Ok(worker_message) = bincode::deserialize::<crate::worker::WorkerMessage>(&batch) {
                        if let crate::worker::WorkerMessage::Batch(_, special_txn_id) = worker_message {
                            if special_txn_id.is_some() {
                                debug!("Forwarding batch with special_txn_id: {:?}", special_txn_id);
                            }
                        }
                    }

                    match self.tx_batch.send(batch).await {
                        Ok(_) => {
                            debug!("Successfully forwarded batch {}", digest);

                        },
                        Err(e) => {
                            warn!("Failed to deliver batch {}: {}", digest, e);
                        }
                    }
                    break;
                }
            }
            
            debug!("\n=== End of Batch {} Processing ===\n", digest);
        }
    }
}

#[cfg(test)]
mod tests {
    // Add your tests here
}