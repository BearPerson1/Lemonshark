// Copyright(C) Facebook, Inc. and its affiliates.
use crate::worker::SerializedBatchDigestMessage;
use config::WorkerId;
use crypto::Digest;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use primary::WorkerPrimaryMessage;
use std::convert::TryInto;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use log::debug;

#[cfg(test)]
#[path = "tests/processor_tests.rs"]
pub mod processor_tests;

/// Indicates a serialized `WorkerMessage::Batch` message.
pub type SerializedBatchMessage = Vec<u8>;

/// Hashes and stores batches, it then outputs the batch's digest.
pub struct Processor;

impl Processor {
    pub fn spawn(
        // Our worker's id.
        id: WorkerId,
        // The persistent storage.
        store: Store,
        // Input channel to receive batches.
        mut rx_batch: Receiver<SerializedBatchMessage>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<SerializedBatchDigestMessage>,
        own_digest: bool,
    ) {
        tokio::spawn(async move {
            while let Some(batch) = rx_batch.recv().await {
                let mut store = store.clone();
                debug!("Receive Channel Capacity: {}", rx_batch.capacity());
                
                // Extract special transaction ID from the batch
                let special_txn_id = match bincode::deserialize(&batch) {
                    Ok(crate::worker::WorkerMessage::Batch(_, special_id)) => special_id,
                    _ => None,
                };

                // Hash the batch.
                let digest = Digest(Sha512::digest(&batch).as_slice()[..32].try_into().unwrap());
                debug!("Processor received digest: {}", digest);
                
                // Clone batch and digest for storage task
                let batch_for_storage = batch.clone();
                let digest_for_storage = digest.clone();
                
                // Spawn storage task
                tokio::spawn(async move {
                    store.write(digest_for_storage.to_vec(), batch_for_storage).await;
                });

                // Only send to primary if own_digest is true
                if own_digest {
                    debug!(
                        "Worker {} sending OurBatch to primary - Digest: {}, Special txn ID: {:?}",
                        id, digest, special_txn_id
                    );
            
                    let message = WorkerPrimaryMessage::OurBatch(digest, id, special_txn_id);
                    
                    let message = bincode::serialize(&message)
                        .expect("Failed to serialize our own worker-primary message");
                    
                    tx_digest
                        .send(message)
                        .await
                        .expect("Failed to send digest");
                    debug!("Send Channel capacity: {}", tx_digest.capacity());
                }
            }
        });
    }
}