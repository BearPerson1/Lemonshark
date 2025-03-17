// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{CertificatesAggregator, VotesAggregator};
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote,ProposerMessage,Metadata};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};


#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<ProposerMessage>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<Digest>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// Aggregates votes into a certificate.
    votes_aggregator: VotesAggregator,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,

    
    // Stuff for lemonshark: 
    cert_timeout: u64,
    certificate_buffers: HashMap<Round, CertificateBuffer>,
    buffer_check_interval: Duration,
    last_buffer_check: Instant,       // When did we last check buffers
    rx_metadata: Receiver<Metadata>,
    completed_round: Round,

}


#[derive(Debug)]
pub struct CertificateBuffer {
    round: Round,
    certs: HashSet<Certificate>,
    last_processed: Instant,  // Track when we last processed this buffer
    metadata: Option<Metadata>, 
}

impl From<tokio::sync::mpsc::error::SendError<(Vec<Certificate>, Round)>> for DagError {
    fn from(e: tokio::sync::mpsc::error::SendError<(Vec<Certificate>, Round)>) -> Self {
        DagError::ProposerSendError(e.to_string())
    }
}

impl From<tokio::sync::mpsc::error::SendError<Certificate>> for DagError {
    fn from(e: tokio::sync::mpsc::error::SendError<Certificate>) -> Self {
        DagError::ConsensusSendError(e.to_string())
    }
}


impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<ProposerMessage>,
        cert_timeout: u64,
        rx_metadata: Receiver<Metadata>
        
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                synchronizer,
                signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                tx_consensus,
                tx_proposer,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                current_header: Header::default(),
                votes_aggregator: VotesAggregator::new(),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                cert_timeout,
                certificate_buffers: HashMap::with_capacity(2 * gc_depth as usize),
                buffer_check_interval: Duration::from_millis(50), // Check every 25ms
                last_buffer_check: Instant::now(),
                rx_metadata,
                completed_round: 0,
            }
            .run()
            .await;
        });
    }


    async fn process_certificate_buffers(&mut self) -> DagResult<()> {
        let now = Instant::now();
        let quorum = self.committee.quorum_threshold() as usize;
    
        debug!("Actually checking certificate buffers");
        // Debug buffer states
        for (round, buffer) in &self.certificate_buffers {
            debug!(
                "Buffer round {}: certs: {}/{} (quorum: {})",
                round,
                buffer.certs.len(),
                self.committee.size(),
                quorum
            );
        }
    
        let mut completed_rounds = Vec::new();
        
        // Find rounds that have metadata AND enough certs for quorum
        for (round, buffer) in &self.certificate_buffers {
            let has_quorum = buffer.certs.len() >= quorum;
            let has_metadata = buffer.metadata.is_some();
    
            // Only process if we have metadata AND quorum of certs
            if has_metadata && has_quorum {
                debug!(
                    "Buffer for round {} is ready for processing.\n\
                    ├─ Has metadata: {}\n\
                    ├─ Has quorum: {} ({}/{} needed)",
                    round,
                    has_metadata,
                    has_quorum,
                    buffer.certs.len(),
                    quorum
                );
                completed_rounds.push(*round);
            } else {
                debug!(
                    "Buffer for round {} not ready.\n\
                    ├─ Has metadata: {}\n\
                    ├─ Has quorum: {} ({}/{} needed)\n\
                    └─ Status: waiting for {}",
                    round,
                    has_metadata,
                    has_quorum,
                    buffer.certs.len(),
                    quorum,
                    if !has_metadata {
                        "metadata"
                    } else {
                        "more certificates"
                    }
                );
            }
        }
    
        // Process completed rounds
        for round in completed_rounds {
            if let Some(buffer) = self.certificate_buffers.remove(&round) {  // This line handles the removal/GC
                // We know metadata exists because of our check above
                let metadata = buffer.metadata.unwrap();
                debug!(
                    "Processing buffer for round {}:\n\
                    ├─ Certificates: {}/{} (quorum: {})\n\
                    ├─ Metadata virtual round: {}\n\
                    └─ Time since last processed: {:?}",
                    round,
                    buffer.certs.len(),
                    self.committee.size(),
                    quorum,
                    metadata.virtual_round,
                    now.duration_since(buffer.last_processed)
                );
    
                let certs: Vec<Certificate> = buffer.certs.into_iter().collect();
                
                if !certs.is_empty() {
                    debug!(
                        "=== Sending Buffered Data for Round {} ===\n\
                        ├─ Metadata virtual round: {}\n\
                        └─ Certificates: {}/{}",
                        round,
                        metadata.virtual_round,
                        certs.len(),
                        quorum
                    );
    
                    // First send metadata
                    if let Err(e) = self.tx_proposer.send(ProposerMessage::Metadata(metadata)).await {
                        warn!("Failed to send metadata to proposer: {}", e);
                        return Err(DagError::ProposerSendError(e.to_string()));
                    }
    
                    // Then send certificates
                    if let Err(e) = self.tx_proposer
                        .send(ProposerMessage::Certificates(certs, round))
                        .await 
                    {
                        warn!("Failed to send certificates to proposer: {}", e);
                        return Err(DagError::ProposerSendError(e.to_string()));
                    }
                }

                // Update round_completed after successful send
                self.completed_round = std::cmp::max(self.completed_round, round);
                debug!("Updated round_completed to {}", self.completed_round);
            }
        }
    
        Ok(())
    }
    
    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing cert {:?}", certificate);
        
        // Process the header embedded in the certificate if we haven't already voted for it
        if !self
            .processing
            .get(&certificate.header.round)
            .map_or_else(|| false, |x| x.contains(&certificate.header.id))
        {
            self.process_header(&certificate.header).await?;
        }
    
        // Ensure we have all ancestors (if we didn't already garbage collect them)
        if certificate.round() > self.gc_round + 1
            && !self.synchronizer.deliver_certificate(&certificate).await?
        {
            debug!(
                "Processing of {:?} suspended: missing ancestors",
                certificate
            );
            return Ok(());
        }
    
        // Store the certificate
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;
    
        let cert_round = certificate.round();

            // Early exit if this round has already been processed
        if cert_round <= self.completed_round {
            debug!(
                "Skipping certificate processing for round {} (already completed up to round {})",
                cert_round,
                self.completed_round
            );


            // send it to consensus layer
            let id = certificate.header.id.clone();
            if let Err(e) = self.tx_consensus.send(certificate).await {
                warn!(
                    "Failed to deliver certificate {} to the consensus: {}",
                    id, e
                );
                return Err(DagError::ConsensusSendError(e.to_string()));
            }

           return Ok(());
        }
            
        // Get or create buffer and add certificate
        let buffer = self.certificate_buffers
            .entry(cert_round)
            .or_insert_with(|| {
                let now = Instant::now();
                debug!(
                    "Creating new buffer for round {}",
                    cert_round
                );
                CertificateBuffer {
                    round: cert_round,
                    certs: HashSet::new(),
                    last_processed: now,
                    metadata: None,
                }
            });
    
        // Add certificate to buffer
        if buffer.certs.insert(certificate.clone()) {
            debug!(
                "Added certificate to buffer - Round: {}, Author: {}, Buffer size: {}",
                cert_round,
                certificate.header.author,
                buffer.certs.len()
            );
        }
    
        // Process any completed buffers
        self.process_certificate_buffers().await?;
    
        // Send certificate to consensus layer
        let id = certificate.header.id.clone();
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
            return Err(DagError::ConsensusSendError(e.to_string()));
        }
        
        Ok(())
    }


    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        debug!("=== Processing Own Header ===");
        debug!(
            "Header details - Round: {}, Author: {}, ID: {}",
            header.round,
            header.author,
            header.id
        );
        // Reset the votes aggregator.
        self.current_header = header.clone();
        self.votes_aggregator = VotesAggregator::new();

        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);



            // Before creating our own vote
         debug!(
                "Checking last_voted state for round {} before voting:",
                header.round
            );
            if let Some(voted) = self.last_voted.get(&header.round) {
                debug!(
                    "Already voted authors for round {}: {:?}",
                    header.round,
                    voted
                );
            }

            // Process the header.
            match self.process_header(&header).await {
                Ok(_) => debug!("Successfully processed own header"),
                Err(e) => debug!("Error processing own header: {:?}", e),
            }
            Ok(())
    

    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        debug!("Processing header {:?}", header);

        debug!("Verbose processing header]: id: {}, round: {}, shard num: {}",
            self.committee.get_primary_id(&header.author),
            header.round,
            header.shard_num
        );

       
        // Indicate that we are processing this header.
        self.processing
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.id.clone());

        // If the following condition is valid, it means we already garbage collected the parents. There is thus
        // no points in trying to synchronize them or vote for the header. We just need to gather the payload.
        if self.gc_round >= header.round {
            if self.synchronizer.missing_payload(header).await? {
                debug!("Downloading the payload of {}", header);
            }
            return Ok(());
        }

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.
        let parents = self.synchronizer.get_parents(header).await?;
        if parents.is_empty() {
            debug!("Processing of {} suspended: missing parent(s)", header.id);
            return Ok(());
        }

        // Check the parent certificates. Ensure the parents form a quorum and are all from the previous round.
        let mut stake = 0;
        for x in parents {
            ensure!(
                x.round() + 1 == header.round,
                DagError::MalformedHeader(header.id.clone())
            );
            stake += self.committee.stake(&x.origin());
        }
        ensure!(
            stake >= self.committee.quorum_threshold(),
            DagError::HeaderRequiresQuorum(header.id.clone())
        );

        // Check weak links. If they are too old, we don't try to synchronize them but we still need to
        // get the payload.
        if !self
            .synchronizer
            .get_weak_links(&header, &self.gc_round)
            .await?
        {
            debug!(
                "Processing of {} suspended: missing weak-link(s)",
                header.id
            );
            return Ok(());
        }

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            debug!("Processing of {} suspended: missing payload", header);
            return Ok(());
        }

        // debug!(
        //     "=== Vote Creation Check ===\nHeader Round: {}\nHeader Author: {}\nHeader ID: {}\nOur Name: {}",
        //     header.round,
        //     header.author,
        //     header.id,
        //     self.name
        // );
 
        // if let Some(voted) = self.last_voted.get(&header.round) {
        //     debug!(
        //         "Current voted authors for round {}: {:?}",
        //         header.round,
        //         voted
        //     );
        // }


        // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.author)
        {
            debug!(
                "Creating vote for header - Author {} was not in last_voted set for round {}",
                header.author,
                header.round
            );
            // Make a vote and send it to the header's creator.
            let vote = Vote::new(header, &self.name, &mut self.signature_service).await;
            debug!("Created {:?}", vote);
            // debug!(
            //     "Vote details:\n Origin: {}\n Target: {}\n Round: {}\n ID: {}",
            //     vote.origin,
            //     vote.author,
            //     vote.round,
            //     vote.id
            // );
            if vote.origin == self.name {
                self.process_vote(vote)
                    .await
                    .expect("Failed to process our own vote");
            } else {
                let address = self
                    .committee
                    .primary(&header.author)
                    .expect("Author of valid header is not in the committee")
                    .primary_to_primary;
                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                    .expect("Failed to serialize our own vote");
                let handler = self.network.send(address, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(header.round)
                    .or_insert_with(Vec::new)
                    .push(handler);
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing vote {:?}", vote);
        debug!(
            "Vote details:\n Origin: {}\n Target: {}\n Round: {}\n ID: {}",
            vote.origin,
            vote.author,
            vote.round,
            vote.id
        );

        debug!(
            "Current header state:\n Round: {}\n Author: {}\n ID: {}",
            self.current_header.round,
            self.current_header.author,
            self.current_header.id
        );
        
        // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(certificate) =
            self.votes_aggregator
                .append(vote, &self.committee, &self.current_header)?
        {
            debug!("Assembled {:?}", certificate);

            // Broadcast the certificate.
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                .expect("Failed to serialize our own certificate");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(certificate.round())
                .or_insert_with(Vec::new)
                .extend(handlers);

            // Process the new certificate.
            self.process_certificate(certificate)
                .await
                .expect("Failed to process valid certificate");
        }
        Ok(())
    }

 

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        //ensure!(
        //    self.gc_round < header.round,
        //    DagError::TooOld(header.id.clone(), header.round)
        //);

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        debug!(
            "=== Sanitizing Vote ===\nVote Round: {}\nCurrent Header Round: {}\nVote ID: {}\nCurrent Header ID: {}\nVote Origin: {}\nCurrent Header Author: {}",
            vote.round,
            self.current_header.round,
            vote.id,
            self.current_header.id,
            vote.origin,
            self.current_header.author
        );
    
        // Check if vote is for an old round
        if self.current_header.round > vote.round {
            debug!(
                "Discarding vote: too old\n├─ Vote round: {}\n└─ Current header round: {}",
                vote.round,
                self.current_header.round
            );
            return Err(DagError::VoteTooOld(vote.digest(), vote.round));
        }
    
        // Check if vote matches expected header
        if vote.id != self.current_header.id 
            || vote.origin != self.current_header.author 
            || vote.round != self.current_header.round {
            debug!(
                "Discarding unexpected vote:\n├─ Vote ID: {} (expected: {})\n├─ Vote origin: {} (expected: {})\n└─ Vote round: {} (expected: {})",
                vote.id,
                self.current_header.id,
                vote.origin,
                self.current_header.author,
                vote.round,
                self.current_header.round
            );
            return Err(DagError::UnexpectedVote(vote.id.clone()));
        }
    
        // Verify the vote
        match vote.verify(&self.committee) {
            Ok(_) => {
                debug!("Vote verification successful");
                Ok(())
            },
            Err(e) => {
                debug!("Vote verification failed: {}", e);
                Err(DagError::from(e))
            }
        }
    }
    
    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        // TODO: Disabling this check is a hack. See TODO in certificate_waiter.

        //ensure!(
        //    self.gc_round < certificate.round(),
        //    DagError::TooOld(certificate.digest(), certificate.round())
        //);

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {

        let mut buffer_check_timer = tokio::time::interval(self.buffer_check_interval);

        loop {
            let result = tokio::select! {
                _ = buffer_check_timer.tick() => {
                    debug!("Timer triggered buffer check");
                    self.process_certificate_buffers().await
                },

                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(&header).await,
                                error => error
                            }

                        },
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => self.process_vote(vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            match self.sanitize_certificate(&certificate) {
                                Ok(()) =>  self.process_certificate(certificate).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here metadata from the consensus layer.
                Some(metadata) = self.rx_metadata.recv() => {
                    debug!(
                        "Received metadata from consensus for virtual round {}",
                        metadata.virtual_round
                    );
                    
                    let round = metadata.virtual_round-1;

                    if round == 0
                    {
                        debug!("round 1");
                        match self.tx_proposer.send(ProposerMessage::Metadata(metadata)).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(DagError::ProposerSendError(e.to_string()))
                        }
                    }
                    else 
                    {
                        let now = Instant::now();
                       // let timeout_duration = Duration::from_millis(self.cert_timeout);
                        
                        // Get or create buffer for this round
                        let buffer = self.certificate_buffers
                            .entry(round)
                            .or_insert_with(|| {
                                debug!(
                                    "Creating new buffer for round {} while processing metadata",
                                    round
                                );
                                CertificateBuffer {
                                    round,
                                    certs: HashSet::new(),
                                    last_processed: now,
                                    metadata: None,
                                }
                            });
                        
                        // Update metadata in buffer
                        buffer.metadata = Some(metadata.clone());
                        debug!(
                            "Updated buffer for round {} with metadata containing {} parents",
                            round,
                            metadata.virtual_parents.len()
                        );
                        // Try processing buffers since we have new metadata
                        self.process_certificate_buffers().await
                    }
                }

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,

                
            };
            match result {
                Ok(()) | Err(DagError::VoteTooOld(..)) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(DagError::ProposerSendError(e)) => {
                    warn!("Failed to send to proposer: {}", e);
                }
                Err(DagError::ConsensusSendError(e)) => {
                    warn!("Failed to send to consensus: {}", e);
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                


                self.last_voted.retain(|k, _| k > &gc_round);
                self.processing.retain(|k, _| k > &gc_round);
                self.certificates_aggregators.retain(|k, _| k > &gc_round);
                self.cancel_handlers.retain(|k, _| k > &gc_round);
                self.gc_round = gc_round;
                self.certificate_buffers.retain(|k, _| k > &gc_round);
            }
        }
    }
}