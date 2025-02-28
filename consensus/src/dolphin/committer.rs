// Copyright(C) Facebook, Inc. and its affiliates.
use crate::dolphin::virtual_state::VirtualState;
use crate::state::{Dag, State};
use config::{Committee, Stake};
use log::{debug, log_enabled};
use primary::{Certificate, Round};
use std::collections::{HashMap,HashSet};
use crypto::PublicKey;


#[derive(Clone)]
pub struct Committer {
    /// The committee information.
    committee: Committee,
    /// The depth of the garbage collection.
    gc_depth: Round,

    last_committed: Round,
}

impl Committer {
    pub fn new(committee: Committee, gc_depth: Round) -> Self {
        Self {
            committee,
            gc_depth,
            last_committed: 0,
        }
    }
// ==================================================================================
    // Lemonshark: Try and commit earlier
// ==================================================================================

// Recursive function to get oldest ancestor 
    pub fn get_oldest_chain_ancestor(
        &self,
        cert: &Certificate, 
        target_shard: u64, 
        current_round: Round, 
        state: &State, 
        indent: &str,
        mapping: &HashMap<PublicKey, u64>
    ) -> Round 
    {
        let mut earliest_round = current_round;
    
        // Only consider parents with matching shard number
        for (parent_id, parent_shard) in &cert.header.parents_id_shard {
            if *parent_shard == target_shard {
                // debug!("{}├─ Parent (Round {}): Primary {}, Shard {}", 
                //       indent, current_round - 1, parent_id, parent_shard);
                
                // Try to find this parent in the previous round
                if current_round > 0 {
                    if let Some(prev_authorities) = state.dag.get(&(current_round - 1)) {
                        for (_, (_, prev_cert)) in prev_authorities {
                            if mapping.get(&prev_cert.header.author).map(|id| *id) == Some(*parent_id) {
                                // Get the earliest round from recursive call
                                let ancestor_earliest = self.get_oldest_chain_ancestor(
                                    prev_cert, 
                                    target_shard, 
                                    current_round - 1, 
                                    state, 
                                    &format!("{}│  ", indent), 
                                    mapping
                                );
                                // Update earliest_round if we found an earlier one
                                earliest_round = earliest_round.min(ancestor_earliest);
                                break;
                            }
                        }
                    }
                }
            }
        }
    
        earliest_round
    }


    pub fn count_certificate_children(
        &self,
        cert: &Certificate,
        round: u64,
        state: &State,
    ) -> (u64, HashMap<u64, u64>) {
        let mut total_children = 0;
        let mut children_per_shard: HashMap<u64, u64> = HashMap::new();
        
        // debug!("\n=== Starting Certificate Children Count ===");
        // debug!("Analyzing certificate from round {} by author {:?}", 
        //        round, 
        //        self.committee.get_all_primary_ids()[&cert.header.author]);
        // debug!("Certificate shard: {}", cert.header.shard_num);

        // Look at the next round in the DAG
        if let Some(next_round_certs) = state.dag.get(&(round + 1)) {
            // debug!("Found {} certificates in round {}", 
            //        next_round_certs.len(), 
            //        round + 1);

            for (auth_key, (_, child_cert)) in next_round_certs {
                // debug!("├─ Checking potential child certificate:");
                // debug!("│  ├─ Author: {:?}", 
                //        self.committee.get_all_primary_ids().get(auth_key));
                // debug!("│  ├─ Shard: {}", child_cert.header.shard_num);
                // debug!("│  └─ Parents count: {}", 
                //        child_cert.header.parents_id_shard.len());

                // Check if this certificate is a parent of the child
                for (parent_id, parent_shard) in &child_cert.header.parents_id_shard {
                    if *parent_id == self.committee.get_all_primary_ids()[&cert.header.author] {
                        // Increment total children count
                        total_children += 1;
                        
                        // Increment the count for this shard
                        *children_per_shard
                            .entry(child_cert.header.shard_num)
                            .or_insert(0) += 1;

                        // debug!("│     ✓ Found child reference!");
                        // debug!("│     ├─ Parent ID: {}", parent_id);
                        // debug!("│     └─ Parent Shard: {}", parent_shard);
                        
                        // Break since we found this parent reference
                        break;
                    }
                }
            }
        } else {
            //debug!("No certificates found in round {}", round + 1);
        }

        // debug!("\n=== Certificate Children Count Summary ===");
        // debug!("Total children found: {}", total_children);
        // // debug!("Children distribution across shards:");
        // // for (shard, count) in &children_per_shard {
        // //     debug!("├─ Shard {}: {} children", shard, count);
        // // }
        // debug!("======================================\n");

        (total_children, children_per_shard)
    }

    // TODO: Optimize the code abit
    // currently it rechecks blocks that already fail the requirements needed for early finality within a finality. 
    pub fn try_early_commit(
        &mut self,
        state: &mut State,
        shard_last_committed_round: &mut HashMap<u64, u64>,
        virtual_round: u64,
    ) -> Vec<Certificate> 
    {
        let mut sequence = Vec::new();

        // f+1 threshold
        let threshold = self.committee.validity_threshold();

        // Create a sorted vector of rounds
        let mut rounds: Vec<_> = state.dag.keys().collect();
        rounds.sort(); // Sort rounds in ascending order

        for &round in &rounds {
            if let Some(authorities) = state.dag.get(&round) {
                for (auth_key, (digest, cert)) in authorities {
                    // Skip if already committed
                    if !state.last_committed.get(auth_key).map_or(true, |last_round| round > last_round) {
                        // debug!("Skipping certificate [round:{} shard:{}] - already committed",cert.header.round,cert.header.shard_num);
                        continue;
                    }
                    // Skip if already early committed. 
                    if state.early_committed_certs.contains(cert) {
                        // debug!("Skipping certificate [round:{} shard:{}] - already early-committed",cert.header.round,cert.header.shard_num);
                        continue;
                    }
                    // skip if checked previously
                    if state.skipped_certs.contains(cert)
                    {
                        // debug!("Skipping certificate [round:{} shard:{}] - already checked",cert.header.round,cert.header.shard_num);

                        continue;
                    }

                    // Skip if cert is in current round
                    if cert.header.round == virtual_round
                    {
                        // debug!("Skipping certificate [round:{} shard:{}] - In same virtual round {} vs {}",cert.header.round,cert.header.shard_num, cert.header.round,virtual_round);
                        continue;
                    }
                    // skip if early fail (collision in shard)
                    if cert.header.cross_shard != 0 {
                        let mut found_matching_cross_shard = false;
                        if let Some(same_round_certs) = state.dag.get(&round) {
                            for (_, (_, cross_cert)) in same_round_certs {
                                // Skip the current cert
                                if cross_cert == cert {
                                    continue;
                                }
                                // Check if this cert is from the target cross-shard
                                if cross_cert.header.shard_num == cert.header.cross_shard {
                                    // Found a matching cross-shard cert in the same round
                                    found_matching_cross_shard = true;
                                    // debug!("Found matching cross-shard cert in round {} for shard {}", 
                                    //     round, cert.header.cross_shard);
                                    break;
                                }
                            }
                        }
                        if !found_matching_cross_shard
                        {
                            // debug!("Cross-shard cert not found");
                            continue;
                        }
                        else 
                        {
                            if cert.header.early_fail
                            {
                                // add to skip list
                                // debug!("early fail!  [primary id:{} round:{} shard:{}]", self.committee.get_primary_id(&cert.header.author), cert.header.round, cert.header.shard_num);
                                state.skipped_certs.insert(cert.clone());
                                continue;
                            }
                        }
                    }

                    // skip if already checked
                    
                    // debug!("Checking certificate children for early commit consideration");
                    let (child_count, shard_counts) = self.count_certificate_children(cert, *round, state);

                    if child_count < threshold.into()
                    {
                        // debug!("insufficient votes");
                        continue;
                    }
                    // debug!("sufficient votes");


                    let target_shard = cert.header.shard_num;
                    // debug!("\nStarting ancestry trace for certificate:");
                    // debug!("Round {}", round);
                    // debug!("├─ Primary: {:?}", self.committee.get_all_primary_ids().get(auth_key));
                    // debug!("├─ Shard: {}", target_shard);
                    // debug!("└─ Cross-shard: {}, {}",cert.header.cross_shard, cert.header.early_fail);
                    // debug!("└─ Ancestry chain (following shard {}):", target_shard);

                    // Start the ancestry trace
                    let mut oldest_chain_ancestor_round = self.get_oldest_chain_ancestor(cert, target_shard, *round, state, "   ", &self.committee.get_all_primary_ids());
                
                    // debug!("The oldest being: {}", oldest_chain_ancestor_round);
                    // debug!("last committed round for this shard: {:?}",shard_last_committed_round.get(&target_shard).copied().unwrap_or(0));

                    // This is where we do our first check:
                    // If it has the chain. 
                    if oldest_chain_ancestor_round - shard_last_committed_round.get(&target_shard).copied().unwrap_or(0) <= 1
                    {
                        // check if crossshard
                        if cert.header.cross_shard != 0
                        {
                            // debug!("Checking Cross-chain");
                            let mut oldest_cross_chain_ancestor_round = self.get_oldest_chain_ancestor(cert,cert.header.cross_shard, *round, state, "   ", &self.committee.get_all_primary_ids());

                            // debug!("The oldest cross being: {}", oldest_cross_chain_ancestor_round);
                            // debug!("last committed round for this shard: {:?}",shard_last_committed_round.get(&cert.header.cross_shard).copied().unwrap_or(0));

                            if oldest_cross_chain_ancestor_round - shard_last_committed_round.get(&cert.header.cross_shard).copied().unwrap_or(0) <= 1
                            {
                                // debug!("Sufficient Chain");
                                // This cert will be early committed., 
                                sequence.push(cert.clone()); 
                            }
                            else 
                            {
                                // debug!("cross-chain not sufficient  [primary id:{} round:{} shard:{}]", self.committee.get_primary_id(&cert.header.author), cert.header.round, cert.header.shard_num);
                                // add to skip list.
                                state.skipped_certs.insert(cert.clone());
                                continue;
                            }
                        }
                        else 
                        {
                            // debug!("Sufficient Chain");
                            // This cert will be early committed., 
                            sequence.push(cert.clone()); 
                        }     
                    }
                    else
                    {
                        // debug!("chain not sufficient:  [primary id:{} round:{} shard:{}]", self.committee.get_primary_id(&cert.header.author), cert.header.round, cert.header.shard_num);
                        state.skipped_certs.insert(cert.clone());
                        // add to skip list
                    }
                    //debug!("===============================");
                }
            }
        }
        sequence
    }  






// ==================================================================================

    /// Try to commit. If we succeed, output am ordered sequence.
    pub fn try_commit(
        &mut self,
        certificate: &Certificate,
        state: &mut State,
        virtual_state: &mut VirtualState,
    ) -> Vec<Certificate> {
        let mut sequence = Vec::new();

        // Update the leader mode to decide whether we can commit the leader.
        let leader = self.update_validator_mode(&certificate, virtual_state);

        //if last_leader.is_none() && certificate.origin() == self.name {
        //    virtual_state.steady = false;
        //}

        if let Some(last_leader) = leader {
            // Print the latest authorities' mode.
            if log_enabled!(log::Level::Debug) {
                virtual_state.print_status(&certificate);
            }

            // Don't double-commit.
            let last_committed_wave = (last_leader.virtual_round() + 1) / 2;
            if self.last_committed >= last_committed_wave {
                return Vec::default();
            }
            self.last_committed = last_committed_wave;

            // Get an ordered list of past leaders that are linked to the current leader.
            for leader in self
                .order_leaders(&last_leader, &virtual_state, last_committed_wave)
                .iter()
                .rev()
            {
                // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                for x in state.flatten(&leader) {
                    // Update and clean up internal state.
                    state.update(&x);
                    // Add the certificate to the sequence.
                    sequence.push(x);
                }
            }

            // Cleanup the virtual dag.
            virtual_state.cleanup(last_leader.virtual_round(), self.gc_depth);
        }
        sequence
    }

    /// Updates the authorities mode (steady state vs fallback) and return whether we can commit
    /// the leader of the wave.
    /// 
    /// 
    fn update_validator_mode(
        &self,
        certificate: &Certificate,
        state: &mut VirtualState,
    ) -> Option<Certificate> {
        let steady_wave = (certificate.virtual_round() + 1) / 2;
        let fallback_wave = (certificate.virtual_round()+ 3) / 4;
        
        debug!(
            "\n=== Processing Validator Mode Update ===\n\
             Certificate ID: {}\n\
             Primary ID: {}\n\
             Certificate Round: {}\n\
             Steady Wave: {}\n\
             Fallback Wave: {}", 
            certificate.header.id,
            self.committee.get_all_primary_ids()[&certificate.header.author],
            certificate.virtual_round(),
            steady_wave,
            fallback_wave
        );


        let prev_in_steady_set = state.steady_authorities_sets
        .entry(steady_wave-1)
        .or_insert_with(HashSet::new)
        .contains(&certificate.origin());
        
        // If this is an even steady wave and the authority was in the previous wave's steady set
        if steady_wave % 2 == 0 && prev_in_steady_set {
            debug!(
                "\n=== Even Steady Wave Processing ===\n\
                Certificate ID: {}\n\
                Primary ID: {}\n\
                ├─ Round: {}\n\
                ├─ Steady Wave: {} (even)\n\
                └─ Status: Previously in Steady Wave {}",
                certificate.header.id,
                self.committee.get_all_primary_ids()[&certificate.header.author],
                certificate.virtual_round(),
                steady_wave,
                steady_wave - 1
            );
            
            // Try to commit the leader of the previous wave
            let leader = self.check_steady_commit(certificate, steady_wave - 1, state);
            
            // Always add the authority to the current wave's steady set
            state.steady_authorities_sets
                .entry(steady_wave)
                .or_insert_with(HashSet::new)
                .insert(certificate.origin());
            
            if let Some(leader_cert) = &leader {
                debug!(
                    "✓ Steady State Leader Commit Successful\n\
                    ├─ Authority maintaining Steady State\n\
                    ├─ Leader Primary ID: {}\n\
                    ├─ Leader Certificate ID: {}\n\
                    └─ Leader Round: {}",
                    self.committee.get_all_primary_ids()[&leader_cert.header.author],
                    leader_cert.header.id,
                    leader_cert.virtual_round()
                );
                return leader;
            } else {
                debug!(
                    "✗ Steady State Leader Commit Failed\n\
                    └─ Still maintaining steady state for authority"
                );
                return None;
            }
        }


            // Determine which set(s) the certificate is in
        let in_steady_set = state.steady_authorities_sets
            .entry(steady_wave)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin());

        let in_fallback_set = state.fallback_authorities_sets
            .entry(fallback_wave)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin());

        if in_steady_set || in_fallback_set {
            debug!(
                "\n=== No Update Needed ===\n\
                Certificate ID: {}\n\
                Primary ID: {}\n\
                ├─ Round: {}\n\
                ├─ Steady Wave: {}\n\
                ├─ Fallback Wave: {}\n\
                ├─ In Steady Set: {}\n\
                └─ In Fallback Set: {}",
                certificate.header.id,
                self.committee.get_all_primary_ids()[&certificate.header.author],
                certificate.virtual_round(),
                steady_wave,
                fallback_wave,
                in_steady_set,
                in_fallback_set
            );
            return None;
        }




    
        // Check steady state transition
        if state.steady_authorities_sets
            .entry(steady_wave - 1)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin())
        {
            debug!(
                "\n=== Checking Steady State Transition ===\n\
                 Certificate ID: {}\n\
                 Primary ID: {}\n\
                 ├─ Round: {}\n\
                 ├─ Previous Wave: {}\n\
                 └─ Status: Previously in Steady State",
                certificate.header.id,
                self.committee.get_all_primary_ids()[&certificate.header.author],
                certificate.virtual_round(),
                steady_wave - 1
            );
            
            let leader = self.check_steady_commit(certificate, steady_wave - 1, state);
            if let Some(leader_cert) = &leader {
                debug!(
                    "✓ 2nd Steady State Commit Successful\n\
                     ├─ Authority maintaining Steady State\n\
                     ├─ Leader Primary ID: {}\n\
                     ├─ Leader Certificate ID: {}\n\
                     └─ Leader Round: {}",
                    self.committee.get_all_primary_ids()[&leader_cert.header.author],
                    leader_cert.header.id,
                    leader_cert.virtual_round()
                );
                state.steady_authorities_sets
                    .get_mut(&steady_wave)
                    .unwrap()
                    .insert(certificate.origin());
                return leader;
            }
            debug!("✗ Steady State Commit Failed - Will Check Fallback");
        }
    
        // Check fallback state transition
        if state.fallback_authorities_sets
            .entry(fallback_wave - 1)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin())
        {
            debug!(
                "\n=== Checking Fallback State Transition ===\n\
                 Certificate ID: {}\n\
                 Primary ID: {}\n\
                 ├─ Round: {}\n\
                 ├─ Previous Wave: {}\n\
                 └─ Status: Previously in Fallback State",
                certificate.header.id,
                self.committee.get_all_primary_ids()[&certificate.header.author],
                certificate.virtual_round(),
                fallback_wave - 1
            );

                
            let leader = self.check_fallback_commit(certificate, fallback_wave - 1, state);
            if let Some(leader_cert) = &leader {
                debug!(
                    "✓ Fallback Commit Successful\n\
                     ├─ Authority promoting to Steady State\n\
                     ├─ Leader Primary ID: {}\n\
                     ├─ Leader Certificate ID: {}\n\
                     └─ Leader Round: {}",
                    self.committee.get_all_primary_ids()[&leader_cert.header.author],
                    leader_cert.header.id,
                    leader_cert.virtual_round()
                );
                state.steady_authorities_sets
                    .get_mut(&steady_wave)
                    .unwrap()
                    .insert(certificate.origin());
                return leader;
            }
            debug!("✗ Fallback Commit Failed - Will Default to Fallback");
        }
    
        debug!(
            "\n=== Defaulting to Fallback State ===\n\
             Certificate ID: {}\n\
             Primary ID: {}\n\
             ├─ Round: {}\n\
             └─ Wave: {}",
            certificate.header.id,
            self.committee.get_all_primary_ids()[&certificate.header.author],
            certificate.virtual_round(),
            fallback_wave
        );
        
        state.fallback_authorities_sets
            .get_mut(&fallback_wave)
            .unwrap()
            .insert(certificate.origin());
    
        None
    }
    
    fn check_steady_commit(
        &self,
        certificate: &Certificate,
        wave: Round,
        state: &VirtualState,
    ) -> Option<Certificate> {
        debug!("\n=== Checking Steady Commit ===");
        debug!(
            "Initiating Certificate:\n\
             ├─ ID: {}\n\
             ├─ Primary ID: {}\n\
             ├─ Round: {}\n\
             └─ Wave: {}",
            certificate.header.id,
            self.committee.get_all_primary_ids()[&certificate.header.author],
            certificate.virtual_round(),
            wave
        );
    
        if let Some((_, leader)) = state.steady_leader(wave) {
            debug!(
                "Steady Leader Found:\n\
                 ├─ Certificate ID: {}\n\
                 ├─ Primary ID: {}\n\
                 ├─ Round: {}\n\
                 └─ Wave: {}", 
                leader.header.id,
                self.committee.get_all_primary_ids()[&leader.header.author],
                leader.virtual_round(),
                wave
            );
            
            let voting_certs = state
                .dag
                .get(&(certificate.virtual_round() - 1))
                .expect("We should have all the history")
                .values()
                .filter(|(digest, parent)| {
                    let is_parent = certificate.virtual_parents().contains(&digest);
                    let is_steady = state
                        .steady_authorities_sets
                        .get(&wave)
                        .map_or_else(|| false, |x| x.contains(&parent.origin()));
                    let is_linked = self.strong_path(parent, leader, &state.dag);
                    
                    if is_parent && is_steady && is_linked {
                        debug!(
                            "Found Voting Certificate:\n\
                             ├─ Certificate ID: {}\n\
                             ├─ Primary ID: {}\n\
                             ├─ Round: {}\n\
                             └─ Is Linked to Leader: true",
                            parent.header.id,
                            self.committee.get_all_primary_ids()[&parent.header.author],
                            parent.virtual_round()
                        );
                    }
                    is_parent && is_steady && is_linked
                })
                .collect::<Vec<_>>();
                
            debug!(
                "Voting Summary:\n\
                 ├─ Total Voting Certificates: {}\n\
                 └─ Required Threshold: {}",
                voting_certs.len(),
                self.committee.validity_threshold()
            );
    
            return if voting_certs.len() >= self.committee.validity_threshold() as usize {
                debug!("✓ Steady Commit Successful");
                Some(leader.clone())
            } else {
                debug!("✗ Steady Commit Failed - Insufficient Votes");
                None
            };
        }
    
        debug!("✗ Steady Commit Failed - No Leader Found");
        None
    }
    
    fn check_fallback_commit(
        &self,
        certificate: &Certificate,
        wave: Round,
        state: &VirtualState,
    ) -> Option<Certificate> {
        debug!("\n=== Checking Fallback Commit ===");
        debug!(
            "Initiating Certificate:\n\
             ├─ ID: {}\n\
             ├─ Primary ID: {}\n\
             ├─ Round: {}\n\
             └─ Wave: {}",
            certificate.header.id,
            self.committee.get_all_primary_ids()[&certificate.header.author],
            certificate.virtual_round(),
            wave
        );

        
        if certificate.virtual_round() < wave * 4 {
            debug!("Cert cannot vote for fallback");
            return None;
        }

        if let Some((_, leader)) = state.fallback_leader(wave) {
            debug!(
                "Fallback Leader Found:\n\
                 ├─ Certificate ID: {}\n\
                 ├─ Primary ID: {}\n\
                 ├─ Round: {}\n\
                 └─ Wave: {}", 
                leader.header.id,
                self.committee.get_all_primary_ids()[&leader.header.author],
                leader.virtual_round(),
                wave
            );
            
            let voting_certs = state
                .dag
                .get(&(leader.virtual_round() + 3))
                .expect("We should have all the history")
                .values()
                .filter(|(digest, parent)| {
                    let is_parent = certificate.virtual_parents().contains(&digest);
                    let is_fallback = state
                        .fallback_authorities_sets
                        .get(&wave)
                        .map_or_else(|| false, |x| x.contains(&parent.origin()));
                    let is_linked = self.strong_path(parent, leader, &state.dag);
                    
                    if is_parent && is_fallback && is_linked {
                        debug!(
                            "Found Voting Certificate:\n\
                             ├─ Certificate ID: {}\n\
                             ├─ Primary ID: {}\n\
                             ├─ Round: {}\n\
                             └─ Is Linked to Leader: true",
                            parent.header.id,
                            self.committee.get_all_primary_ids()[&parent.header.author],
                            parent.virtual_round()
                        );
                    }
                    is_parent && is_fallback && is_linked
                })
                .collect::<Vec<_>>();
                
            debug!(
                "Voting Summary:\n\
                 ├─ Total Voting Certificates: {}\n\
                 └─ Required Threshold: {}",
                voting_certs.len(),
                self.committee.validity_threshold()
            );
    
            return if voting_certs.len() >= self.committee.validity_threshold() as usize {
                debug!("✓ Fallback Commit Successful");
                Some(leader.clone())
            } else {
                debug!("✗ Fallback Commit Failed - Insufficient Votes");
                None
            };
        }
    
        debug!("✗ Fallback Commit Failed - No Leader Found");
        None
    }

    /// Checks if there is a path between two leaders.
    fn strong_path(&self, leader: &Certificate, prev_leader: &Certificate, dag: &Dag) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.virtual_round()..leader.virtual_round()).rev() {
            parents = dag
                .get(&r)
                .expect("We should have the whole history by now")
                .values()
                .filter(|(digest, _)| {
                    parents
                        .iter()
                        .any(|x| x.virtual_parents().contains(&digest))
                })
                .map(|(_, certificate)| certificate)
                .collect();
        }
        parents.contains(&prev_leader)
    }

    /// Order the past leaders that we didn't already commit.
    fn order_leaders(
        &self,
        leader: &Certificate,
        state: &VirtualState,
        last_committed_wave: Round,
    ) -> Vec<Certificate> {
        let mut to_commit = vec![leader.clone()];
        let steady_wave = (leader.virtual_round() + 1) / 2;
        let mut leader = leader;
        debug!("ORDERING LEADERS");
        for w in (last_committed_wave + 1..steady_wave).rev() {
            debug!("checking wave: {}",w);
            let (_, v) = state
                .dag
                .get(&(2 * w - 1))
                .expect("We should have at least one node")
                .get(&leader.origin())
                .expect("Certificates have parents of the same author");
            let votes: Vec<_> = state
                .dag
                .get(&(v.virtual_round() - 1))
                .expect("We should have the whole history")
                .values()
                .filter(|(x, _)| v.virtual_parents().contains(&x))
                .map(|(_, x)| x)
                .collect();

            let steady_leader = state.steady_leader(w).map(|(_, x)| x);
            debug!("steady leader wave: {}",w);
            let steady_votes: Stake = steady_leader.map_or_else(
                || 0,
                |leader| {
                    votes
                        .iter()
                        .filter(|voter| {
                            state.steady_authorities_sets.get(&w).map_or_else(
                                || false,
                                |x| {
                                    x.contains(&voter.origin())
                                        && self.strong_path(voter, leader, &state.dag)
                                },
                            )
                        })
                        .map(|voter| self.committee.stake(&voter.origin()))
                        .sum()
                },
            );

            let fallback_leader = state.fallback_leader((w+1) / 2).map(|(_, x)| x);
            debug!("fallback leader wave: {}",(w+1)/2);
            let mut fallback_votes: Stake = fallback_leader.map_or_else(
                || 0,
                |leader| {
                    votes
                        .iter()
                        .filter(|voter| {
                            state.fallback_authorities_sets.get(&((w+1)/ 2)).map_or_else(
                                || false,
                                |x| {
                                    x.contains(&voter.origin())
                                        && self.strong_path(voter, leader, &state.dag)
                                },
                            )
                        })
                        .map(|voter| self.committee.stake(&voter.origin()))
                        .sum()
                },
            );
            if w % 2 != 0 {
                fallback_votes = 0;
            }

            if let Some(steady_leader) = steady_leader {
                if steady_votes >= self.committee.validity_threshold()
                    && fallback_votes < self.committee.validity_threshold()
                {
                    to_commit.push(steady_leader.clone());
                    leader = steady_leader
                }
            }

            if let Some(fallback_leader) = fallback_leader {
                if fallback_votes >= self.committee.validity_threshold()
                    && steady_votes < self.committee.validity_threshold()
                {
                    to_commit.push(fallback_leader.clone());
                    leader = fallback_leader
                }
            }
        }
        to_commit
    }
}
