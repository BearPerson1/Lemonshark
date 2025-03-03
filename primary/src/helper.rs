// Copyright(C) Facebook, Inc. and its affiliates.
use crate::primary::PrimaryMessage;
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use log::{error, warn};
use network::ReliableSender;
use store::Store;
use tokio::sync::mpsc::Receiver;
use std::time::Duration;

/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive certificates requests.
    rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: ReliableSender,
}

impl Helper {
    pub fn spawn(
        committee: Committee,
        store: Store,
        rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_primaries,
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((digests, origin)) = self.rx_primaries.recv().await {
            // TODO [issue #195]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.primary(&origin) {
                Ok(x) => x.primary_to_primary,
                Err(e) => {
                    warn!("Unexpected certificate request: {}", e);
                    continue;
                }
            };

            // Reply to the request (the best we can).
            for digest in digests {
                match self.store.read(digest.to_vec()).await {
                    Ok(Some(data)) => {
                        // TODO: Remove this deserialization-serialization in the critical path.
                        let certificate = bincode::deserialize(&data)
                            .expect("Failed to deserialize our own certificate");
                        let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate))
                            .expect("Failed to serialize our own certificate");
                        // Using ReliableSender's send method and handling the cancel_handler
                        let cancel_handler = self.network.send(address, Bytes::from(bytes)).await;
                        
                        // Optional: Wait for acknowledgment with timeout
                        tokio::spawn(async move {
                            match tokio::time::timeout(Duration::from_secs(5), cancel_handler).await {
                                Ok(Ok(_)) => (),  // Successfully delivered
                                Ok(Err(e)) => warn!("Failed to deliver certificate: {:?}", e),
                                Err(_) => warn!("Certificate delivery timed out"),
                            }
                        });
                    }
                    Ok(None) => (),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}