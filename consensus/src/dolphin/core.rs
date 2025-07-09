// Copyright(C) Facebook, Inc. and its affiliates.
use crate::dolphin::committer::Committer;
use crate::dolphin::virtual_state::VirtualState;
use crate::state::State;
use config::{Committee, Stake};
use crypto::Hash as _;
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Metadata, Round};

use std::collections::{HashMap, HashSet, BTreeSet};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use crypto::PublicKey;
use std::sync::Arc;
use tokio::sync::Mutex;
use crypto::Digest;

use primary::messages::Header;  // We already have Header from primary
use primary::ClientMessage;

pub struct Dolphin {
    /// The committee information.
    committee: Committee,
    /// The leader timeout value.
    timeout: u64,
    /// The garbage collection depth.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_certificate: Receiver<Certificate>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_commit: Sender<Certificate>,
    /// Sends the virtual parents to the primary's core.
    tx_core:Sender<Metadata>, // New channel to send metadata to Core
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
    /// The virtual dag round to share with the primary.
    virtual_round: Round,
    /// Implements the commit logic and returns an ordered list of certificates.
    committer: Committer,

    // lemonshark stuff:
    // This delimits how far the chain has to check. 
    // <shard, round num = u64>
    shard_last_committed_round: HashMap<u64,u64>,

    cross_shard_occurance_rate: f64,
    cross_shard_failure_rate: f64,
    causal_transactions_collision_rate: f64,
    causal_transactions_respect_early_finality: bool,
    tx_client: Sender<ClientMessage>,
    name: PublicKey,
    cert_timeout: u64,
    cert_timer:Option<Instant>,

}

impl Dolphin {
    async fn with_state<F, R>(&self, state: &Arc<Mutex<State>>, f: F) -> R 
    where
        F: FnOnce(&mut State) -> R,
    {
        let mut state_guard = state.lock().await;
        f(&mut state_guard)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        committee: Committee,
        timeout: u64,
        gc_depth: Round,
        rx_certificate: Receiver<Certificate>,
        tx_commit: Sender<Certificate>,
        tx_core: Sender<Metadata>,
        tx_output: Sender<Certificate>,
        cross_shard_occurance_rate: f64,
        cross_shard_failure_rate: f64,
        causal_transactions_collision_rate: f64,
        causal_transactions_respect_early_finality: bool,
        tx_client: Sender<ClientMessage>, 
        name: PublicKey,
        cert_timeout: u64,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                timeout,
                gc_depth,
                rx_certificate,
                tx_commit,
                tx_core,
                tx_output,
                genesis: Certificate::genesis(&committee),
                virtual_round: 0,
                committer: Committer::new(committee, gc_depth),
                shard_last_committed_round: HashMap::new(),
                cross_shard_occurance_rate,
                cross_shard_failure_rate,
                causal_transactions_collision_rate,
                causal_transactions_respect_early_finality,
                tx_client,
                name,
                cert_timeout,
                cert_timer: None,
            }
            .run()
            .await;
        });
    }

    fn init_shard_last_committed_round(&mut self) {
        for id in 1..=self.committee.size() {
            self.shard_last_committed_round.insert(id as u64, 0);
        }
    }

    fn print_shard_last_committed_round(&mut self) {
        debug!("Shard Last Committed Rounds:");
        // Create a vector of keys and sort them
        let mut shard_nums: Vec<_> = self.shard_last_committed_round.keys().collect();
        shard_nums.sort();
        
        // Print each shard's information in sorted order
        for shard_num in shard_nums {
            if let Some(round) = self.shard_last_committed_round.get(shard_num) {
                debug!("├─ Shard {}: Round {}", shard_num, round);
            }
        }
        debug!("=======================================");
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let state = Arc::new(Mutex::new(State::new(self.gc_depth, self.genesis.clone())));
        let mut virtual_state = VirtualState::new(self.committee.clone(), self.genesis.clone());

        // Init the shard_last_committed_round()
        self.init_shard_last_committed_round();

        // The timer keeping track of the leader timeout.
        let timer = sleep(Duration::from_millis(self.timeout));
        tokio::pin!(timer);

        let mut quorum = Some(self.genesis.iter().map(|x| (x.digest(), 0)).collect());
        let mut advance_early = true;

        let select_timer_timeout = 25;
        let select_timer = sleep(Duration::from_millis(select_timer_timeout));
        tokio::pin!(select_timer);


        loop {

            // create timer
            if quorum.is_some() && self.cert_timer.is_none() {
                self.cert_timer = Some(Instant::now());
                debug!(
                    "Starting certificate timeout timer for round {}",
                    self.virtual_round
                );
            }

            // Check if cert timeout has expired
            // Why? Leader timeout applies only if not early advance. 
            // in early advance, we wanna wait abit so we can get more stuff, to prevent missed consensus. 
            let cert_timeout_expired = self.cert_timer
            .map(|start_time| start_time.elapsed() >= Duration::from_millis(self.cert_timeout))
            .unwrap_or(false);
            
            let full_quorum = virtual_state.dag
            .get(&self.virtual_round)
            .map_or(false, |round_certs| {
                let participating_nodes = round_certs
                    .values()
                    .map(|(_, cert)| cert.origin())
                    .collect::<HashSet<_>>()
                    .len();
                participating_nodes == self.committee.size()
            });

            //// todo: remove
            // debug!(
            //     "=== Header Proposal Condition Check ===\n\
            //      ├─ Timer Status:\n\
            //      │  ├─ Elapsed: {}\n\
            //      │  └─ Max Delay: {} ms\n\
            //      ├─ Certificate Timer Status:\n\
            //      │  ├─ Started: {}\n\
            //      │  ├─ Expired: {}\n\
            //      │  └─ Timeout: {} ms\n\
            //      ├─ Advance Status:\n\
            //      │  ├─ advance_early: {}\n\
            //      │  └─ virtual_round: {}\n\
            //      ├─ Quorum Status:\n\
            //      │  ├─ has_quorum: {}\n\
            //      │  ├─ total_stake: {}\n\
            //      │  └─ threshold: {}\n\
            //      └─ Combined Check: ((elapsed || advance_early) && (has_quorum && cert_timeout_expired) || full_quorum): {}",
            //     timer.is_elapsed(),
            //     self.timeout,
            //     self.cert_timer.is_some(),
            //     cert_timeout_expired,
            //     self.cert_timeout,
            //     advance_early,
            //     self.virtual_round,
            //     quorum.is_some(),
            //     virtual_state.dag.get(&self.virtual_round)
            //         .map_or(0, |round_certs| round_certs.values()
            //             .map(|(_, cert)| self.committee.stake(&cert.origin()))
            //             .sum::<Stake>()),
            //     self.committee.quorum_threshold(),
            //     ((timer.is_elapsed() || advance_early) && (quorum.is_some() && cert_timeout_expired) || full_quorum)
            // );
            
            // debug!("Advance early check");
            if self.virtual_round > 1
            {
                advance_early = match self.virtual_round % 2 {
                    0 => {
    
                        // we creating header for odd (we in even round now)
                        true
                    },
                    _ => {
                        // we creating header for even (we in odd round now)
                        // self.enough_votes(self.virtual_round, &virtual_state)


                        // we creating header for odd
                        let fallback_wave = (self.virtual_round+3)/4;
                        //debug!("advance early wave: {}",fallback_wave);

                        let in_fallback = virtual_state.fallback_authorities_sets.get(&fallback_wave)
                            .map_or(false, |set| set.contains(&self.name));
                
                        if in_fallback {
                            true  // Return true if in fallback
                        } else {
                            // Return true if not in fallback but has steady leader
                            virtual_state.steady_leader((self.virtual_round+1)/2).is_some() 
                        }
                    } 
                };
            }
            //debug!("Advance early check for round {}: {}", self.virtual_round, advance_early);




            if ((timer.is_elapsed() || advance_early) && (quorum.is_some() && cert_timeout_expired) || full_quorum) {
                if !advance_early {
                    warn!(
                        "Timing out for round {}, moving to the next round",
                        self.virtual_round
                    );
                }
                if(full_quorum) {
                    warn!(
                        "Full quorum for round {}, moving to the next round",
                        self.virtual_round
                    );
                }



                // todo remove DEBUG
                self.with_state(&state, |state| {
                    state.print_state(self.committee.get_all_primary_ids());
                }).await;

                // Advance to the next round.
                self.virtual_round += 1;
                debug!("Virtual dag moved to round {}", self.virtual_round);
                // Send the virtual parents to the primary's proposer.

                // Reset the cert timer when advancing rounds
                self.cert_timer = None;

                self.tx_core
                .send( Metadata::new(self.virtual_round, quorum.unwrap()))
                .await
                .expect("Failed to send metadata to primary core");

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.timeout);
                timer.as_mut().reset(deadline);

                // Reset the quorum.
                quorum = None;
            }

            tokio::select! {
                Some(certificate) = self.rx_certificate.recv() => {
                    debug!("Processing cert {:?}", certificate);
                    // debug!("[extra info:] [name:{} id:{} round:{} shard:{}]",
                    //     certificate.header.author,
                    //     self.committee.get_primary_id(&certificate.header.author),
                    //     certificate.header.round,
                    //     certificate.header.shard_num
                    // );
                    let virtual_round = certificate.virtual_round();

                    // Add the new certificate to the local storage
                    self.with_state(&state, |state| {
                        state.add(certificate.clone());
                    }).await;

                    // Try adding the certificate to the virtual dag
                    if !virtual_state.try_add(&certificate) {
                        continue;
                    }
                    debug!("Adding virtual {:?}", certificate);

                    // Try to commit
                    let sequence = {
                        let mut state_guard = state.lock().await;
                        self.committer.try_commit(&certificate, &mut state_guard, &mut virtual_state)
                    };


                    if !sequence.is_empty() {
                        // lemonshark: clean up checked list
                        self.with_state(&state, |state| {
                            state.skipped_certs.clear();
                            // Reset all SBO values back to None for all certificates in the state
                            for (_, round_certs) in state.dag.iter_mut() {
                                for (_, (_digest, cert)) in round_certs.iter_mut() {
                                    cert.header.SBO = None;
                                }
                            }
                        }).await;
                    }

                    // Log the latest committed round of every authority (for debug)
                    if log_enabled!(log::Level::Debug) {
                        let state_guard = state.lock().await;
                        for (name, round) in &state_guard.last_committed {
                            debug!("Latest commit of {}| id:{} : Round {}",
                                name,
                                self.committee.get_primary_id(name),
                                round
                            );
                        }
                    }

                    // Output the sequence in the right order.
                    for certificate in sequence {
                        #[cfg(not(feature = "benchmark"))]
                        info!("Committed {}", certificate.header);

                        // Update shard_last_committed_round
                        if *self.shard_last_committed_round.get(&certificate.header.shard_num).unwrap_or(&0) < certificate.header.round {
                            self.shard_last_committed_round.insert(certificate.header.shard_num, certificate.header.round);
                        }

                        // GC for state.early_committed_certs
                        self.with_state(&state, |state| {
                            state.remove_early_committed_certs(&certificate);
                        }).await;

                        // debug!("[extra info:] [name:{} id:{} round:{} shard:{}]",
                        //     certificate.header.author,
                        //     self.committee.get_primary_id(&certificate.header.author),
                        //     certificate.header.round,
                        //     certificate.header.shard_num
                        // );

                        #[cfg(feature = "benchmark")]
                        for digest in certificate.header.payload.keys() {
                            info!("Committed {} -> {:?}", certificate.header, digest);
                        }

                            // Check if we need to send a client message
                        if certificate.header.casual_transaction && certificate.header.author == self.name {
                            // Create clones only if we need to spawn
                            let certificate_clone = certificate.clone();
                            let tx_client_clone = self.tx_client.clone();
                            
                            tokio::spawn(async move {
                                let msg = ClientMessage {
                                    header: certificate_clone.header.clone(),
                                    message_type: 1,  // 1 for Certificate
                                };
                                
                                if let Err(e) = tx_client_clone.send(msg).await {
                                    warn!("Failed to send certificate to client: {}", e);
                                } else {
                                    debug!("Successfully sent committed certificate to client - Round: {}, Shard: {}",
                                        certificate_clone.header.round,
                                        certificate_clone.header.shard_num
                                    );
                                }
                            });
                        }

                        self.tx_commit
                            .send(certificate.clone())
                            .await
                            .expect("Failed to send committed certificate to primary");

                        if let Err(e) = self.tx_output.send(certificate).await {
                            warn!("Failed to output certificate: {}", e);
                        }
                    }
                    // Print debug state

                    // self.with_state(&state, |state| {
                    //     state.print_state(self.committee.get_all_primary_ids());
                    // }).await;
                    // self.print_shard_last_committed_round();

                    // Early commit processing
                    let state_clone = Arc::clone(&state);
                    let mut shard_last_committed_round_clone = self.shard_last_committed_round.clone();
                    let tx_client_clone = self.tx_client.clone();
                    let name = self.name;
                    let mut committer_clone = self.committer.clone();
                    let causal_transactions_respect_early_finality = self.causal_transactions_respect_early_finality;
                    let certificate_clone = certificate.clone();


                    // // send the stuff to the client (causal transactions)
                    // tokio::spawn(async move {
                    //     if certificate_clone.header.casual_transaction && certificate_clone.header.author == name {
                    //         let msg = ClientMessage {
                    //             header: certificate_clone.header.clone(),
                    //             message_type: 1,  // 1 for Certificate
                    //         };
                    
                    //         if let Err(e) = tx_client_clone.send(msg).await {
                    //             warn!("Failed to send certificate to client: {}", e);
                    //         } else {
                    //             debug!("Successfully sent committed certificate to client - Round: {}, Shard: {}",
                    //                 certificate_clone.header.round,
                    //                 certificate_clone.header.shard_num
                    //             );
                    //         }
                    //     }
                    // });

                    // let tx_client_clone = self.tx_client.clone();
                    // let name = self.name;

                    tokio::spawn(async move {
                        let early_commit_result = {
                            let mut state_guard = state_clone.lock().await;
                            committer_clone.try_early_commit(
                                &mut state_guard,
                                &mut shard_last_committed_round_clone,
                                virtual_round as u64
                            )
                        };

                        for certificate in &early_commit_result {
                            #[cfg(feature = "benchmark")]
                            for digest in certificate.header.payload.keys() {
                                // NOTE: this is for perf eval
                                info!("Early-Committed {} -> {:?}", certificate.header, digest);
                            }

                            if causal_transactions_respect_early_finality &&
                               certificate.header.casual_transaction &&
                               certificate.header.author == name {
                                let mut header = certificate.header.clone();
                                // if early committment is possible, collision should be impossible. 
                                header.collision_fail = false;
                                let msg = ClientMessage {
                                    header,
                                    message_type: 1,
                                };
                                debug!("Sending early committed certificate to client - Round: {}, Shard: {}", certificate.header.round, certificate.header.shard_num);
                                if let Err(e) = tx_client_clone.send(msg).await {
                                    warn!("Failed to send early commit certificate to client: {}", e);
                                } else {
                                    debug!(
                                        "Successfully sent early committed certificate to client - Round: {}, Shard: {}",
                                        certificate.header.round,
                                        certificate.header.shard_num
                                    );
                                }
                            }
                        }

                        for certificate in &early_commit_result {
                            // Add to state
                            let mut state_guard = state_clone.lock().await;
                            state_guard.add_early_committed_certs(certificate.clone());
                        }



                    });


                    debug!(
                        "Virtual round sync check - current: {}, certificate: {}, advance_early: {}, has_quorum: {}",
                        self.virtual_round,
                        virtual_round,
                        advance_early,
                        quorum.is_some()
                    );

                    // Round advancement logic
                    if self.virtual_round != virtual_round {
                        continue;
                    }
                    debug!("Trying to advance virtual round");

                    let (parents, authors): (BTreeSet<_>, Vec<_>) = virtual_state
                        .dag
                        .get(&virtual_round)
                        .expect("We just added a certificate with this round")
                        .values()
                        .map(|(digest, x)| ((digest.clone(), x.virtual_round()), x.origin()))
                        .collect::<Vec<_>>()
                        .iter()
                        .cloned()
                        .unzip();

                    quorum = (authors
                        .iter()
                        .map(|x| self.committee.stake(x))
                        .sum::<Stake>() >= self.committee.quorum_threshold())
                        .then(|| parents);
                    debug!("Got quorum for round {}: {}", self.virtual_round, quorum.is_some());

                    // todo remove
                    debug!(
                        "Quorum status for virtual round {}: has_quorum={}, authors_stake={}, threshold={}",
                        self.virtual_round,
                        quorum.is_some(),
                        authors.iter().map(|x| self.committee.stake(x)).sum::<Stake>(),
                        self.committee.quorum_threshold()
                    );

                    // it sort of makes sense that if theres a leader this round, we might want to have it's cert so we can vote on it. 
                    // therefore, we might wanna wait abit longer just incase 

                    //debug!("[2]Advance early check");
                    if self.virtual_round > 1
                    {
                        advance_early = match self.virtual_round % 2 {
                            0 => {
            
                                // we creating header for odd (we in even round now)
                                true
                            },
                            _ => {
                                // we creating header for even (we in odd round now)
                                // self.enough_votes(self.virtual_round, &virtual_state)
        
        
                                // we creating header for odd
                                let fallback_wave = (self.virtual_round+3)/4;
                               // debug!("advance early wave: {}",fallback_wave);
        
                                let in_fallback = virtual_state.fallback_authorities_sets.get(&fallback_wave)
                                    .map_or(false, |set| set.contains(&self.name));
                        
                                if in_fallback {
                                    true  // Return true if in fallback
                                } else {
                                    // Return true if not in fallback but has steady leader
                                    virtual_state.steady_leader((self.virtual_round+1)/2).is_some() 
                                }
                            } 
                        };
                    }



                    advance_early = match virtual_round % 2 {
                        0 => self.enough_votes(virtual_round, &virtual_state) || !advance_early,
                        _ => virtual_state.steady_leader((virtual_round+1)/2).is_some(),
                    };
                   debug!("[2]Advance early check for round {}: {}", self.virtual_round, advance_early);
                },
                () = &mut select_timer => {
                    // Reset select timer
                      select_timer.as_mut().reset(Instant::now() + Duration::from_millis(select_timer_timeout));
                }
            }
        }
    }

    /// Check if we gathered a quorum of votes for the leader.
    fn enough_votes(&mut self, virtual_round: Round, virtual_state: &VirtualState) -> bool {
        let wave = (virtual_round + 1) / 2;
        virtual_state.steady_leader(wave - 1).map_or_else(
            || false,
            |(leader_digest, _)| {
                // Either we got 2f+1 votes for the leader.
                virtual_state
                    .dag
                    .get(&virtual_round)
                    .expect("We just added a certificate with this round")
                    .values()
                    .filter(|(_, x)| x.virtual_parents().contains(&leader_digest))
                    .map(|(_, x)| self.committee.stake(&x.origin()))
                    .sum::<Stake>()
                    >= self.committee.quorum_threshold()

                // Or we go f+1 votes that are not for the leader.
                    || virtual_state
                        .dag
                        .get(&virtual_round)
                        .expect("We just added a certificate with this round")
                        .values()
                        .filter(|(_, x)| !x.virtual_parents().contains(&leader_digest))
                        .map(|(_, x)| self.committee.stake(&x.origin()))
                        .sum::<Stake>()
                        >= self.committee.validity_threshold()
            },
        )
    }
}
