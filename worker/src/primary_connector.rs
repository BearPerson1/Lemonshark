// Copyright(C) Facebook, Inc. and its affiliates.
use crate::worker::SerializedBatchDigestMessage;
use bytes::Bytes;
use network::SimpleSender;  
use std::net::SocketAddr;
use tokio::sync::mpsc::Receiver;
use log::debug;  // Added for debug logging

// Send batches' digests to the primary.
pub struct PrimaryConnector {
    /// The primary network address.
    primary_address: SocketAddr,
    /// Input channel to receive the digests to send to the primary.
    rx_digest: Receiver<SerializedBatchDigestMessage>,
    /// A network sender to send the batches' digests to the primary.
    network: SimpleSender,  
}

impl PrimaryConnector {
    pub fn spawn(primary_address: SocketAddr, rx_digest: Receiver<SerializedBatchDigestMessage>) {
        tokio::spawn(async move {
            Self {
                primary_address,
                rx_digest,
                network: SimpleSender::new(),  // Changed from 
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some(digest) = self.rx_digest.recv().await {
            // Send the digest through the network and wait for confirmation
            let bytes = Bytes::from(digest.clone());
            
            debug!("Sending batch digest {:?} to primary at {}", digest, self.primary_address);
            debug!("Channel Capacity: {}",self.rx_digest.capacity());
            self.network
                .send(self.primary_address,bytes)
                .await;
            // Use the reliable sender and get the cancel handler
            // let handler = self.network
            //     .send(self.primary_address, bytes)
            //     .await;

            // // Wait for the message to be delivered or cancelled
            // if let Ok(_) = handler.await {
            //     debug!("Batch digest {:?} successfully delivered to primary at {}", digest, self.primary_address);
            // } else {
            //     debug!("Failed to deliver batch digest to primary at {}", self.primary_address);
            // }
        }
    }
}