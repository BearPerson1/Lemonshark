// Copyright(C) Facebook, Inc. and its affiliates.
use crate::dolphin::committer::Committer;
use crate::dolphin::virtual_state::VirtualState;
use crate::state::State;
use config::{Committee, Stake};
use crypto::Hash as _;
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Metadata, Round};
use std::collections::BTreeSet;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use crypto::PublicKey;
use std::collections::HashMap;

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
    /// Sends the virtual parents to the primary's proposer.
    tx_parents: Sender<Metadata>,
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
    shard_last_committed_round: HashMap <u64,u64>,

    cross_shard_occurance_rate: f64,
    cross_shard_failure_rate: f64,
    causal_transactions_collision_rate: f64,
    causal_transactions_respect_early_finality: bool,
    tx_client: Sender<ClientMessage>,
    name: PublicKey,
   

}



impl Dolphin {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        committee: Committee,
        timeout: u64,
        gc_depth: Round,
        rx_certificate: Receiver<Certificate>,
        tx_commit: Sender<Certificate>,
        tx_parents: Sender<Metadata>,
        tx_output: Sender<Certificate>,
        cross_shard_occurance_rate: f64,
        cross_shard_failure_rate: f64,
        causal_transactions_collision_rate: f64,
        causal_transactions_respect_early_finality: bool,
        tx_client: Sender<ClientMessage>, 
        name: PublicKey,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                timeout,
                gc_depth,
                rx_certificate,
                tx_commit,
                tx_parents,
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
            }
            .run()
            .await;
        });
    }

    fn init_shard_last_committed_round(&mut self)
    {
        for id in 1..=self.committee.size()
        {
            self.shard_last_committed_round.insert(id as u64 ,0);
        }
    }

    fn print_shard_last_committed_round(&mut self)
    {
        debug!("Shard Last Committed Rounds:");
        // Create a vector of keys and sort them
        let mut shard_nums: Vec<_> = self.shard_last_committed_round.keys().collect();
        shard_nums.sort();
        
        // Print each shard's information in sorted order
        for shard_num in shard_nums 
        {
            if let Some(round) = self.shard_last_committed_round.get(shard_num) 
            {
                debug!("├─ Shard {}: Round {}", shard_num, round);
            }
        }
        debug!("=======================================");
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.gc_depth, self.genesis.clone());
        let mut virtual_state = VirtualState::new(self.committee.clone(), self.genesis.clone());

        // Init the shard_last_committed_round()
        self.init_shard_last_committed_round();


        // The timer keeping track of the leader timeout.
        let timer = sleep(Duration::from_millis(self.timeout));
        tokio::pin!(timer);

        let mut quorum = Some(self.genesis.iter().map(|x| (x.digest(), 0)).collect());
        let mut advance_early = true;


        loop {
            if (timer.is_elapsed() || advance_early) && quorum.is_some() {
                if !advance_early {
                    warn!(
                        "Timing out for round {}, moving to the next round",
                        self.virtual_round
                    );
                }
                // Advance to the next round.
                self.virtual_round += 1;
                debug!("Virtual dag moved to round {}", self.virtual_round);
                // Send the virtual parents to the primary's proposer.
                self.tx_parents
                    .send(Metadata::new(self.virtual_round, quorum.unwrap()))
                    .await
                    .expect("Failed to send virtual parents to primary");


                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.timeout);
                timer.as_mut().reset(deadline);

                // Reset the quorum.
                quorum = None;
            }

            tokio::select! {
                Some(certificate) = self.rx_certificate.recv() => {
                    debug!("Processing cert {:?}", certificate);
                    debug!("[extra info:] [name:{} id:{} round:{} shard:{}]",certificate.header.author,
                        self.committee.get_primary_id(&certificate.header.author), certificate.header.round, 
                        certificate.header.shard_num
                        );
                    let virtual_round = certificate.virtual_round();

                    // Add the new certificate to the local storage.
                    state.add(certificate.clone());

                    // Try adding the certificate to the virtual dag.
                    if !virtual_state.try_add(&certificate) {
                        continue;
                    }
                    debug!("Adding virtual {:?}", certificate);

                    // Try to commit.
                    let sequence = self.committer.try_commit(&certificate, &mut state, &mut virtual_state);

                   if !sequence.is_empty()
                   {
                    // lemonshark: clean up checked list
                        state.skipped_certs.clear();
                   }

                    // Log the latest committed round of every authority (for debug).
                    if log_enabled!(log::Level::Debug) {
                        for (name, round) in &state.last_committed {
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


                        // lemonshark: send it to client
                        // todo: change some logic
                        if certificate.header.casual_transaction && certificate.header.author == self.name
                        {
                            let msg = ClientMessage {
                                header: certificate.header.clone(),
                                message_type: 1,  // 1 for Certificate
                            };
    
                            if let Err(e) = self.tx_client.send(msg).await {
                                warn!("Failed to send certificate to client: {}", e);
                            } else {
                                debug!("Successfully sent committed certificate to client - Round: {}, Shard: {}", 
                                    certificate.header.round, 
                                    certificate.header.shard_num);
                            }
                        }
                        // =================================

                        // Lemonshark: verytime a commit is performed, we will have to update shard_last_committed_round
                        if *self.shard_last_committed_round.get(&certificate.header.shard_num).unwrap_or(&0) < certificate.header.round
                        {
                            self.shard_last_committed_round.insert(certificate.header.shard_num,certificate.header.round);
                        }

                        // lemonshark: do some GC for state.early_committed_certs
                        state.remove_early_committed_certs(&certificate);


                        debug!("[extra info:] [name:{} id:{} round:{} shard:{}]",certificate.header.author,
                        self.committee.get_primary_id(&certificate.header.author), certificate.header.round, 
                        certificate.header.shard_num
                        );


                        #[cfg(feature = "benchmark")]
                        for digest in certificate.header.payload.keys() {
                            // NOTE: This log entry is used to compute performance.
                            info!("Committed {} -> {:?}", certificate.header, digest);

                        }

                        self.tx_commit
                            .send(certificate.clone())
                            .await
                            .expect("Failed to send committed certificate to primary");

                        if let Err(e) = self.tx_output.send(certificate).await {
                            warn!("Failed to output certificate: {}", e);
                        }
                    }
// =======================================================================
// Lemonshark
// =======================================================================
                    // TODO: remove
                    state.print_state(self.committee.get_all_primary_ids());
                    self.print_shard_last_committed_round();

                    // Lemonshark: Try and eary commit
                    // NOTE: This runs every time a certificate is added, but must happen after a potential commit. 


                    // let early_commit_sequence = self.committer.try_early_commit(&mut state, &mut self.shard_last_committed_round, virtual_round as u64);
                    // for certificate in early_commit_sequence {
                    //     state.add_early_committed_certs(certificate.clone());
                    //     #[cfg(feature = "benchmark")]
                    //     for digest in certificate.header.payload.keys() {
                    //         // NOTE: This log entry is used to compute performance.
                    //         // TODO: change this so that benchmark can regex it in logs.py
                    //         info!("Early Committed {} -> {:?}", certificate.header, digest); 
                    //     }
                    // }


                    let mut state_clone = state.clone();  
                    let mut shard_last_committed_round_clone = self.shard_last_committed_round.clone();
                    let tx_client_clone = self.tx_client.clone();
                    let name = self.name;  
                    let mut committer_clone = self.committer.clone();  
                    let causal_transactions_respect_early_finality = self.causal_transactions_respect_early_finality;
                    // Parallelize it slightly

                    
                    tokio::spawn(async move {
                        let early_commit_result = committer_clone.try_early_commit(
                            &mut state_clone,
                            &mut shard_last_committed_round_clone,
                            virtual_round as u64
                        );
                    
                        // Rest of the spawned task remains the same
                        for certificate in early_commit_result {
                            state_clone.add_early_committed_certs(certificate.clone());
                            
                            #[cfg(feature = "benchmark")]
                            {
                                for digest in certificate.header.payload.keys() {
                                    info!("Early-Committed {} -> {:?}", certificate.header, digest);
                                }
                            }
                    
                            // Send to client if needed
                            if causal_transactions_respect_early_finality
                            {
                                if certificate.header.casual_transaction && certificate.header.author == name {
                                    let msg = ClientMessage {
                                        header: certificate.header.clone(),
                                        message_type: 1,
                                    };
                        
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
                    
                        }
                    });
//======================================================================

                    // If the certificate is not from our virtual round, it cannot help us advance round.
                    if self.virtual_round != virtual_round {
                        continue;
                    }
                    debug!("Trying to advance round");

                    // Try to advance to the next (virtual) round.
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

                    //if authors.iter().any(|x| x == &self.name) {
                    quorum = (authors
                        .iter()
                        .map(|x| self.committee.stake(x))
                        .sum::<Stake>() >= self.committee.quorum_threshold())
                        .then(|| parents);
                    debug!("Got quorum for round {}: {}", self.virtual_round, quorum.is_some());

                    advance_early = match virtual_round % 2 {
                        0 => self.enough_votes(virtual_round, &virtual_state) || !advance_early,
                        _ => virtual_state.steady_leader((virtual_round+1)/2).is_some(),
                    };
                    debug!("Can early advance for round {}: {}", self.virtual_round, advance_early);
                    //}




                },
                () = &mut timer => {
                    // Nothing to do.
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
