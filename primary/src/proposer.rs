// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Metadata;
use crate::messages::{Certificate, Header};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
#[cfg(feature = "benchmark")]
use log::info;
use log::{debug, log_enabled};
use std::collections::VecDeque;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use std::collections::BTreeSet;
use rand::Rng;

use crate::primary::ClientMessage;

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(Vec<Certificate>, Round)>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(Digest, WorkerId)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,
    /// The current consensus round.
    rx_consensus: Receiver<Metadata>,

    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Digest>,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(Digest, WorkerId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// The metadata to include in the next header.
    metadata: VecDeque<Metadata>,

    // Lemonshark:
    committee: Committee,
    last_parent_certificates: Vec<Certificate>,
    cross_shard_occurance_rate: f64,
    cross_shard_failure_rate: f64,
    causal_transactions_collision_rate: f64,
    tx_client: Sender<ClientMessage>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<(Vec<Certificate>, Round)>,
        rx_workers: Receiver<(Digest, WorkerId)>,
        tx_core: Sender<Header>,
        rx_consensus: Receiver<Metadata>,
        cross_shard_occurance_rate: f64,
        cross_shard_failure_rate: f64,
        causal_transactions_collision_rate: f64,
        tx_client: Sender<ClientMessage>,
        
    ) {
        let genesis = Certificate::genesis(committee)
            .iter()
            .map(|x| x.digest())
            .collect();

        let committee_clone = committee.clone(); // Clone the committee
        tokio::spawn(async move {
            Self {
                name,
                signature_service,
                header_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                rx_consensus,
                round: 1,
                last_parents: genesis,
                digests: Vec::with_capacity(2 * header_size),
                payload_size: 0,
                metadata: VecDeque::new(),
                committee:committee_clone,
                last_parent_certificates: Vec::new(),
                cross_shard_occurance_rate,
                cross_shard_failure_rate,
                causal_transactions_collision_rate,
                tx_client,
                
            }
            .run()
            .await;
        });
    }

    // Function to determine which shard this current header should work on
    // By default its done in a round robin manner dependant on the primary_id value. 
    fn determine_shard_num(&self, primary_id:u64, round_num: u64, committee_size:u64)->u64{
        let temp = (primary_id + round_num - 1) % committee_size;
        if temp == 0 
        { 
            committee_size
        }
        else 
        {
            temp
        }
    }
    
    // function to roll a dice to decide if this shard is cross-shard
    // if yes, it takes another shard thats not itself. 
    // currently it just picks a random other 
    fn determine_cross_shard(&self, shard_num: u64) -> (u64, bool) {
        // do we cross-shard?
        if rand::thread_rng().gen_bool(self.cross_shard_occurance_rate) {
            let mut rng = rand::thread_rng();
            let mut cross_shard_num = rng.gen_range(1,self.committee.size()) as u64;
            
            if cross_shard_num == shard_num {
                cross_shard_num = if cross_shard_num >= self.committee.size() as u64 {
                    1
                } else {
                    cross_shard_num + 1
                };
            }

            if rand::thread_rng().gen_bool(self.cross_shard_failure_rate) {
                (cross_shard_num, true)
            } else {
                (cross_shard_num, false)
            }
        } else {
            // no cross-shard
            // by default its false. 
            (0, false)
        }
    }

    
    async fn make_header(&mut self) {
        // Make a new header.
        
        
        let shard_num = self.determine_shard_num(self.committee.get_primary_id(&self.name), self.round, self.committee.size() as u64);
        
        debug!("Creating new header for [primary: {}, round: {}, shard num: {}]",self.committee.get_primary_id(&self.name),self.round,shard_num);
        let mut parents_id_shard = BTreeSet::new();
        let (cross_shard,early_fail) : (u64,bool) = self.determine_cross_shard(shard_num);


        for parent_cert in &self.last_parent_certificates 
        { 
            let primary_id = self.committee.get_primary_id(&parent_cert.header.author);
            let parent_shard = parent_cert.header.shard_num;
            parents_id_shard.insert((primary_id, parent_shard));
        }

        debug!(
            "[Primary: {}] Creating header with parents_id_shard: {:?} for round {} shard {}", 
            self.committee.get_primary_id(&self.name),
            parents_id_shard,
            self.round,
            shard_num
        ); 
        if cross_shard != 0
        {
            debug!("Cross-shard going to shard {}, early fail->{}",cross_shard,early_fail);
        }



        let header = Header::new(
            self.name,
            self.round,
            self.digests.drain(..).collect(),
            self.last_parents.drain(..).collect(),
            self.metadata.pop_back(),
            &mut self.signature_service,
            shard_num,
            parents_id_shard, 
            cross_shard,
            early_fail,
        )
        .await;
        debug!("Created header {:?}", header);
        if log_enabled!(log::Level::Debug) {
            if let Some(metadata) = header.metadata.as_ref() {
                debug!(
                    "{} contains virtual round {}",
                    header, metadata.virtual_round
                );
                debug!(
                    "{} virtual parents are {:?}",
                    header, metadata.virtual_parents
                );
            }
        }

        #[cfg(feature = "benchmark")]
        for digest in header.payload.keys() {
            // NOTE: This log entry is used to compute performance.
            info!("Created {} -> {:?}", header, digest);
        }
        // TODO: add more logic
        let _ = self.tx_client.send(ClientMessage::Header(header.clone())).await;

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.round);

        let timer = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);

        loop {
            // Check if we can propose a new header. We propose a new header when one of the following
            // conditions is met:
            // 1. We have a quorum of certificates from the previous round and enough batches' digests;
            // 2. We have a quorum of certificates from the previous round and the specified maximum
            // inter-header delay has passed.
            let enough_parents = !self.last_parents.is_empty();
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();
            let metadata_ready = !self.metadata.is_empty();
            if (timer_expired || enough_digests) && enough_parents && metadata_ready {
                // Make a new header.
                self.make_header().await;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

            tokio::select! {
                Some((parent_certs, round)) = self.rx_core.recv() => {
                    if round < self.round {
                        continue;
                    }

                    // Advance to the next round.
                    self.round = round + 1;
                    debug!("Dag moved to round {}", self.round);

                    // Signal that we have enough parent certificates to propose a new header.
                    self.last_parents = parent_certs.iter().map(|cert| cert.digest()).collect();
                    self.last_parent_certificates = parent_certs;

                }
                Some((digest, worker_id)) = self.rx_workers.recv() => {
                    self.payload_size += digest.size();
                    self.digests.push((digest, worker_id));
                }
                Some(metadata) = self.rx_consensus.recv() => {
                    self.metadata.push_front(metadata);
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}
