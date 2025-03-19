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
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(test)]
#[path = "tests/quorum_waiter_tests.rs"]
pub mod quorum_waiter_tests;

#[derive(Debug)]
pub struct QuorumWaiterMessage {
    pub batch: SerializedBatchMessage,
    pub handlers: Vec<(PublicKey, CancelHandler)>,
}

type StakeFuture = Pin<Box<dyn Future<Output = Stake> + Send>>;

// Separate the voting status into two parts:
// 1. Cloneable data
#[derive(Debug, Clone)]
struct BatchMetadata {
    batch: SerializedBatchMessage,
    total_stake: Stake,
    votes_received: u64,
    digest: String,
    special_txn_id: Option<u64>,
}

// 2. Non-cloneable futures
struct BatchVotingStatus {
    metadata: BatchMetadata,
    wait_for_quorum: FuturesUnordered<StakeFuture>,
}

pub struct QuorumWaiter {
    committee: Committee,
    stake: Stake,
    rx_message: Receiver<QuorumWaiterMessage>,
    tx_batch: Sender<SerializedBatchMessage>,
}

impl QuorumWaiter {
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

    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    fn calculate_digest(batch: &[u8]) -> String {
        let hash = Sha512::digest(batch);
        let digest_bytes: [u8; 32] = hash.as_slice()[..32].try_into()
            .expect("Failed to create digest");
        format!("{:?}", crypto::Digest(digest_bytes))
    }

    fn process_new_batch(
        &self,
        batch: &SerializedBatchMessage,
        digest: &str,
        handlers: Vec<(PublicKey, CancelHandler)>,
    ) -> Option<BatchVotingStatus> {
        match bincode::deserialize::<crate::worker::WorkerMessage>(batch) {
            Ok(crate::worker::WorkerMessage::Batch(txs, special_txn_id)) => {
                // debug!("\n=== New Batch Added to Buffer ===");
                // debug!("Batch digest: {}", digest);
                // debug!("Total transactions: {}", txs.len());
                // debug!("Batch size: {} bytes", batch.len());
                // debug!("Special transaction ID: {:?}", special_txn_id);
                // debug!("Expected quorum threshold: {}", self.committee.quorum_threshold());
                // debug!("Starting stake (self): {}", self.stake);

                let wait_for_quorum: FuturesUnordered<StakeFuture> = handlers
                    .into_iter()
                    .map(|(name, handler)| {
                        let stake = self.committee.stake(&name);
                        Box::pin(Self::waiter(handler, stake)) as StakeFuture
                    })
                    .collect();

                let metadata = BatchMetadata {
                    batch: batch.clone(),
                    total_stake: self.stake,
                    votes_received: 0,
                    digest: digest.to_string(),
                    special_txn_id,
                };

                Some(BatchVotingStatus {
                    metadata,
                    wait_for_quorum,
                })
            },
            _ => {
                warn!("Invalid batch message received");
                None
            }
        }
    }

    async fn process_batch_votes(
        status: &mut BatchVotingStatus,
        committee: &Committee,
        tx_batch: &Sender<SerializedBatchMessage>,
    ) -> bool {

        while let Some(stake) = status.wait_for_quorum.next().await {
            status.metadata.total_stake += stake;
            status.metadata.votes_received += 1;
            // debug!("\nReceived vote {} for batch {}", status.metadata.votes_received, status.metadata.digest);
            // debug!("Vote stake value: {}", stake);
            // debug!("Current total stake: {}/{}", status.metadata.total_stake, committee.quorum_threshold());

            if status.metadata.total_stake >= committee.quorum_threshold() {
                // debug!("\n=== Quorum Reached for Batch {} ===", status.metadata.digest);
                // debug!("Final total stake: {}", status.metadata.total_stake);
                // debug!("Total votes received: {}", status.metadata.votes_received);
                
                if let Some(txn_id) = status.metadata.special_txn_id {
                    // debug!("Forwarding batch with special_txn_id: {:?}", txn_id);
                }

                if let Err(e) = tx_batch.send(status.metadata.batch.clone()).await {
                    // warn!("Failed to deliver batch {}: {}", status.metadata.digest, e);
                } else {
                    debug!("Successfully forwarded batch {}", status.metadata.digest);
                    debug!("Channel capacity remaining: {}", tx_batch.capacity());
                    return true; // Batch completed
                }
                break;
            }
        }

        false // Batch still needs more votes
    }

    async fn run(&mut self) {
        // Create a shared batch buffer
        let batch_buffer: Arc<Mutex<HashMap<Vec<u8>, BatchVotingStatus>>> = Arc::new(Mutex::new(HashMap::new()));
        
        // Spawn the parallel batch checker
        let checker_batch_buffer = batch_buffer.clone();
        let committee = self.committee.clone();
        let tx_batch = self.tx_batch.clone();
        
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_millis(50));
            
            loop {
                check_interval.tick().await;
                
                let mut buffer = checker_batch_buffer.lock().await;
                let mut completed_batches = Vec::new();

                // Process each batch
                for (key, status) in buffer.iter_mut() {
                    if Self::process_batch_votes(status, &committee, &tx_batch).await {
                        completed_batches.push(key.clone());
                    }
                }

                // Remove completed batches
                for key in completed_batches {
                    buffer.remove(&key);
                }

                // Drop the lock
                drop(buffer);
            }
        });
        
        // Main loop only handles new messages
        while let Some(QuorumWaiterMessage { batch, handlers }) = self.rx_message.recv().await {
            let digest = Self::calculate_digest(&batch);
            
            // Process and store new batch
            if let Some(status) = self.process_new_batch(&batch, &digest, handlers) {
                let mut buffer = batch_buffer.lock().await;
                buffer.insert(batch.clone(), status);
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