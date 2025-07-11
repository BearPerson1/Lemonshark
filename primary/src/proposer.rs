// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Metadata;
use crate::messages::{Certificate, Header, ProposerMessage};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
#[cfg(feature = "benchmark")]
use log::info;
use log::{debug, log_enabled,warn};
use std::collections::VecDeque;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use std::collections::{BTreeSet,HashMap};
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
    rx_core: Receiver<ProposerMessage>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(Digest, WorkerId,Option<u64>)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,
    /// The current consensus round.
    //rx_consensus: Receiver<Metadata>,

    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Digest>,
    /// FIFO queue for digests with their sizes
    digest_queue: VecDeque<(Digest, WorkerId, Option<u64>, usize)>,
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
    cross_shard_count: u64,
    multi_home_appearance_rate: f64,
    faults: u64,
}



impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<ProposerMessage>,
        rx_workers: Receiver<(Digest, WorkerId, Option<u64>)>,  
        tx_core: Sender<Header>,
        //rx_consensus: Receiver<Metadata>,
        cross_shard_occurance_rate: f64,
        cross_shard_failure_rate: f64,
        causal_transactions_collision_rate: f64,
        tx_client: Sender<ClientMessage>,
        cross_shard_count: u64,
        multi_home_appearance_rate: f64, 
        faults: u64,
        
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
                //rx_consensus,
                round: 1,
                last_parents: genesis,
                digest_queue: VecDeque::new(),
                payload_size: 0,
                metadata: VecDeque::new(),
                committee:committee_clone,
                last_parent_certificates: Vec::new(),
                cross_shard_occurance_rate,
                cross_shard_failure_rate,
                causal_transactions_collision_rate,
                tx_client,
                cross_shard_count,
                multi_home_appearance_rate,
                faults,
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
// function to determine cross-shard targets and their success/failure status
    fn determine_cross_shard(&self, shard_num: u64) -> HashMap<u64, bool> {
        let mut cross_shard_map = HashMap::new();
        
        // Check if we should do cross-shard operations
        if rand::thread_rng().gen_bool(self.cross_shard_occurance_rate) {
            let mut rng = rand::thread_rng();
            
            // Determine how many shards to pick (0 to cross_shard_count)
            let num_shards_to_pick = rng.gen_range(0, self.cross_shard_count + 1);
            
            // Create a vector of possible shard numbers (excluding our own shard)
            let mut possible_shards: Vec<u64> = (1..=self.committee.size() as u64)
                .filter(|&x| x != shard_num)
                .collect();
                
            // Shuffle the possible shards
            for i in (1..possible_shards.len()).rev() {
                let j = rng.gen_range(0, i + 1);
                possible_shards.swap(i, j);
            }
            
            // Take the first num_shards_to_pick shards and determine their success/failure
            for &target_shard in possible_shards.iter().take(num_shards_to_pick as usize) {
                // For each selected shard, flip a coin to decide success/failure
                let will_succeed = !rand::thread_rng().gen_bool(self.cross_shard_failure_rate);
                cross_shard_map.insert(target_shard, will_succeed);
            }
        }
        
        cross_shard_map
    }

    fn determine_multi_home_failure(&self) -> u64 {
        if rand::thread_rng().gen_bool(self.multi_home_appearance_rate) {
            // Multi-homed transaction - simulate attempts to reach healthy nodes
            let total_nodes = self.committee.size() as u64;
            let success_probability = (total_nodes - self.faults) as f64 / total_nodes as f64;
            
            let mut failure_count = 0;
            let max_attempts = self.faults; // Maximum number of attempts/flips
            
            for _ in 0..max_attempts {
                if rand::thread_rng().gen_bool(success_probability) {
                    // Success - we reached a healthy node
                    return failure_count;
                } else {
                    // Failed attempt - increment counter and try again
                    failure_count += 1;
                }
            }
            
            // If we've exhausted all attempts, return the failure count
            failure_count
        } else {
            0  // Normal transaction - no failures
        }
    }

    // flip coin to see if collision happens. 
    fn determine_causal_collision(&self) -> bool {
        rand::thread_rng().gen_bool(self.causal_transactions_collision_rate)
    }
    
    async fn make_header(&mut self) {
        // Get the shard number
        let shard_num = self.determine_shard_num(self.committee.get_primary_id(&self.name), self.round, self.committee.size() as u64);
        let mut causal_transaction:bool = false;
        let mut causal_transaction_id:u64 = 0;
        let mut collision_fail:bool = false;

        // Take digests from queue until we reach header_size
        let mut current_size = 0;
        let mut selected_digests = Vec::new();
        
        while let Some((digest, worker_id, special_id, size)) = self.digest_queue.pop_front() {
            if current_size + size > self.header_size {
                // Put this digest back as it would exceed the size
                self.digest_queue.push_front((digest, worker_id, special_id, size));
                break;
            }
            
            current_size += size;
            
            // Check for special transaction
            if let Some(id) = special_id {
                
                causal_transaction = true;
                causal_transaction_id = id;
                collision_fail = self.determine_causal_collision();
            }
            
            selected_digests.push((digest, worker_id, special_id));
        }

        // Update payload_size to reflect what's left in the queue
        self.payload_size = self.digest_queue.iter().map(|(_, _, _, size)| size).sum();


        // lemonshark: Shard management
        let mut parents_id_shard = BTreeSet::new();
        let cross_shard_map: HashMap<u64, bool> = self.determine_cross_shard(shard_num);

        for parent_cert in &self.last_parent_certificates 
        { 
            let primary_id = self.committee.get_primary_id(&parent_cert.header.author);
            let parent_shard = parent_cert.header.shard_num;
            parents_id_shard.insert((primary_id, parent_shard));
        }

        debug!(
            "[Primary: {}] Creating header with parents_id_shard: {:?} for round {} shard {}, size: {}", 
            self.committee.get_primary_id(&self.name),
            parents_id_shard,
            self.round,
            shard_num, 
            current_size
        ); 

        let mut multi_home_wait_time = 0; // Default value, will be updated if needed
        if !cross_shard_map.is_empty() {
            debug!("Cross-shard mappings: {:?}", cross_shard_map);

            // Determine if this is a multi-home transaction
            multi_home_wait_time = self.determine_multi_home_failure();
            debug!("Multi-home wait time: {}", multi_home_wait_time);
        }

        // todo: delete
        // some debug statements
        debug!("Creating new header for [primary: {}, round: {}, shard num: {}]",self.committee.get_primary_id(&self.name),self.round,shard_num);
       
        if causal_transaction
        {
            debug!("Header has causal transaction: [causal_txn_id: {}, fail?: {}]",causal_transaction_id,collision_fail);
        }

        let header = Header::new(
            self.name,
            self.round,
            selected_digests.into_iter().map(|(d, w, _)| (d, w)).collect(),
            self.last_parents.drain(..).collect(),
            self.metadata.pop_back(),
            &mut self.signature_service,
            shard_num,
            parents_id_shard, 
            cross_shard_map,
            causal_transaction,
            causal_transaction_id,
            collision_fail,
            None,
            multi_home_wait_time, 
        )
        .await;
        debug!("Created header {:?}", header);
        if log_enabled!(log::Level::Debug) {
            if let Some(metadata) = header.metadata.as_ref() {
                debug!(
                    "{} contains virtual round {}",
                    header, metadata.virtual_round -1
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

        // Lemonshark: If this includes a causal transaction, we send our "spec" to the client
        if causal_transaction
        {
            let msg = ClientMessage {
                header: header.clone(),
                message_type: 0,  // 0 for Header
            };
            
            if let Err(e) = self.tx_client.send(msg).await {
                warn!("Failed to send header to client: {}", e);
            } else {
                debug!("Successfully sent header to client - Round: {}, Shard: {}", 
                    header.round, 
                    header.shard_num);
            }
        }
        
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
            let enough_digests = self.digest_queue
                .iter()
                .map(|(_, _, _, size)| size)
                .sum::<usize>() >= self.header_size;
            let timer_expired = timer.is_elapsed();
            let metadata_ready = !self.metadata.is_empty();


            // // todo remove:
            // if enough_parents {
            //     debug!(
            //         "Header proposal conditions for round {}: metadata_ready={}, enough_digests={}, timer_expired={}, payload_size={}/{}",
            //         self.round,
            //         metadata_ready,
            //         enough_digests,
            //         timer_expired,
            //         self.payload_size,
            //         self.header_size
            //     );
            // }

            if (timer_expired || enough_digests) && enough_parents && metadata_ready {
                // Make a new header.
                self.make_header().await;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

            tokio::select! {
                Some(message) = self.rx_core.recv() => {
                    match message {
                        ProposerMessage::Certificates(parent_certs, round) => {
                            if round < self.round {
                                continue;
                            }

                            // Print header proposal conditions before advancing round
                            debug!(
                                "Final header proposal conditions for round {}: metadata_ready={}, enough_digests={}, timer_expired={}, payload_size={}/{}, parent_count_in cert={}",
                                self.round,
                                !self.metadata.is_empty(),
                                self.payload_size >= self.header_size,
                                timer.is_elapsed(),
                                self.payload_size,
                                self.header_size,
                                parent_certs.len()
                            );

                            // Add detailed parent certificates logging
                            debug!("=== Parent Certificates Details ===");
                            for (index, cert) in parent_certs.iter().enumerate() {
                                debug!(
                                    "Parent[{}]: Primary ID: {}, Shard: {}, Round: {}", 
                                    index,
                                    self.committee.get_primary_id(&cert.header.author),
                                    cert.header.shard_num,
                                    cert.header.round
                                );
                            }
                            debug!("================================");
                            //bug fix maybe???
                            if !self.metadata.is_empty() && !self.last_parents.is_empty() {
                                debug!(
                                    "[Pre-Round-Advance] Proposing header with metadata for round {}. All conditions met: metadata_ready=true, parent_count={}, payload_size={}/{}",
                                    round ,
                                    self.last_parents.len(),
                                    self.payload_size,
                                    self.header_size
                                );

                                // Make a header with current round before advancing
                                self.make_header().await;
                              //  self.payload_size = 0;

                                debug!("Successfully proposed pre-round-advance header for round {}", self.round);
                            } else {
                                debug!(
                                    "[Pre-Round-Advance] Cannot propose header for round {}: metadata_ready={}, parent_count={}",
                                    round,
                                    !self.metadata.is_empty(),
                                    self.last_parents.len()
                                );
                            }
                            self.round = round + 1;
                            debug!("Dag moved to round {}", self.round);

                            // Signal that we have enough parent certificates to propose a new header.
                            self.last_parents = parent_certs.iter().map(|cert| cert.digest()).collect();
                            self.last_parent_certificates = parent_certs;
                        }
                        ProposerMessage::Metadata(metadata) => {
                            self.metadata.push_front(metadata);
                        }
                    }
                }

                Some((digest, worker_id, special_txn_id)) = self.rx_workers.recv() => {
                    //todo: delete
                    debug!("=== Received Batch from Worker ===");
                    debug!("Worker ID: {}", worker_id);
                    debug!("Special Transaction ID: {:?}", special_txn_id);
                    debug!("Received Digest: {:?}", digest);
                    debug!("Current Payload Size: {} bytes", self.payload_size);
                    debug!("Digest Size: {} bytes", digest.size());
                    debug!("Current Number of Digests: {}", self.digest_queue.len());
                    
                    
                    let digest_size = digest.size();

                    self.digest_queue.push_back((digest, worker_id, special_txn_id, digest_size));
                    self.payload_size += digest_size;
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}