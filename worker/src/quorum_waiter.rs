// Copyright(C) Facebook, Inc. and its affiliates.
use crate::processor::SerializedBatchMessage;
use config::{Committee, Stake};
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::Future;
use network::CancelHandler;
use tokio::sync::mpsc::{Receiver, Sender};
use log::{debug, warn};
use ed25519_dalek::Sha512;
use ed25519_dalek::Digest as _;
use std::convert::TryInto;
use std::collections::HashMap;
use std::pin::Pin;
use tokio::time::{interval, Duration};
use futures::StreamExt;

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

// Define the future type explicitly
type StakeFuture = Pin<Box<dyn Future<Output = Stake> + Send>>;

/// Tracks the voting status of a single batch
#[derive(Debug)]
struct BatchVotingStatus {
    batch: SerializedBatchMessage,
    total_stake: Stake,
    votes_received: u64,
    digest: String,
    special_txn_id: Option<u64>,
    wait_for_quorum: FuturesUnordered<StakeFuture>,
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

    /// Calculate batch digest
    fn calculate_digest(batch: &[u8]) -> String {
        let hash = Sha512::digest(batch);
        let digest_bytes: [u8; 32] = hash.as_slice()[..32].try_into()
            .expect("Failed to create digest");
        format!("{:?}", crypto::Digest(digest_bytes))
    }

    /// Process a new batch and return its voting status
    fn process_new_batch(
        &self,
        batch: &SerializedBatchMessage,
        digest: &str,
        handlers: Vec<(PublicKey, CancelHandler)>,
    ) -> Option<BatchVotingStatus> {
        match bincode::deserialize::<crate::worker::WorkerMessage>(batch) {
            Ok(crate::worker::WorkerMessage::Batch(txs, special_txn_id)) => {
                debug!("\n=== New Batch Added to Buffer ===");
                debug!("Batch digest: {}", digest);
                debug!("Total transactions: {}", txs.len());
                debug!("Batch size: {} bytes", batch.len());
                debug!("Special transaction ID: {:?}", special_txn_id);
                debug!("Expected quorum threshold: {}", self.committee.quorum_threshold());
                debug!("Starting stake (self): {}", self.stake);

                let wait_for_quorum: FuturesUnordered<StakeFuture> = handlers
                    .into_iter()
                    .map(|(name, handler)| {
                        let stake = self.committee.stake(&name);
                        Box::pin(Self::waiter(handler, stake)) as StakeFuture
                    })
                    .collect();

                Some(BatchVotingStatus {
                    batch: batch.clone(),
                    total_stake: self.stake, // Start with own stake
                    votes_received: 0,
                    digest: digest.to_string(),
                    special_txn_id,
                    wait_for_quorum,
                })
            },
            _ => {
                warn!("Invalid batch message received");
                None
            }
        }
    }

    /// Main loop.
    async fn run(&mut self) {
        // Create a buffer to store batches and their voting status
        let mut batch_buffer: HashMap<Vec<u8>, BatchVotingStatus> = HashMap::new();
        
        // Create an interval timer for periodic checks (every 100ms)
        let mut check_interval = interval(Duration::from_millis(100));
        
        loop {
            tokio::select! {
                // Branch 1: Receive new messages
                maybe_message = self.rx_message.recv() => {
                    let QuorumWaiterMessage { batch, handlers } = match maybe_message {
                        Some(msg) => msg,
                        None => break, // Channel closed
                    };

                    let digest = Self::calculate_digest(&batch);
                    
                    // Process and store new batch
                    if let Some(status) = self.process_new_batch(&batch, &digest, handlers) {
                        batch_buffer.insert(batch.clone(), status);
                    }
                }

                // Branch 2: Process the timer tick to check quorum
                _ = check_interval.tick() => {
                    let mut completed_batches = Vec::new();

                    // Check each batch in the buffer
                    for (batch_key, status) in batch_buffer.iter_mut() {
                        // Process any new votes that have arrived
                        while let Some(stake) = status.wait_for_quorum.next().await {
                            status.total_stake += stake;
                            status.votes_received += 1;
                            debug!("\nReceived vote {} for batch {}", status.votes_received, status.digest);
                            debug!("Vote stake value: {}", stake);
                            debug!("Current total stake: {}/{}", status.total_stake, self.committee.quorum_threshold());

                            // Check if we've reached quorum immediately after receiving a vote
                            if status.total_stake >= self.committee.quorum_threshold() {
                                debug!("\n=== Quorum Reached for Batch {} ===", status.digest);
                                debug!("Final total stake: {}", status.total_stake);
                                debug!("Total votes received: {}", status.votes_received);
                                
                                if let Some(txn_id) = status.special_txn_id {
                                    debug!("Forwarding batch with special_txn_id: {:?}", txn_id);
                                }

                                // Send the batch that reached quorum
                                if let Err(e) = self.tx_batch.send(status.batch.clone()).await {
                                    warn!("Failed to deliver batch {}: {}", status.digest, e);
                                } else {
                                    debug!("Successfully forwarded batch {}", status.digest);
                                    completed_batches.push(batch_key.clone());
                                }
                                break;  // Exit the vote processing loop once quorum is reached
                            }
                        }
                    }

                    // Remove completed batches from buffer
                    for batch_key in completed_batches {
                        batch_buffer.remove(&batch_key);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::channel;
    use std::time::Duration;

    #[tokio::test]
    async fn test_quorum_waiter_basic() {
        // Test implementation here
    }
}