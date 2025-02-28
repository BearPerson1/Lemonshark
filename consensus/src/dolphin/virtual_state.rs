// Copyright(C) Facebook, Inc. and its affiliates.
use crate::state::Dag;
use config::Committee;
use crypto::{Digest, Hash as _, PublicKey};
use log::debug;
use primary::{Certificate, Round};
use std::collections::{HashMap, HashSet};
use sha2::{Sha256, Digest as Sha256Digest};
use std::convert::TryInto;

/// The virtual consensus state. This state is interpreted from metadata included in the certificates
/// and can be derived from the real state (`State`).
pub struct VirtualState {
    /// The committee information.
    committee: Committee,
    /// Keeps the latest committed certificate (and its children) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    pub dag: Dag,
    /// Keeps tracks of authorities is in the steady state.
    pub steady_authorities_sets: HashMap<Round, HashSet<PublicKey>>,
    /// Keeps tracks of authorities in the fallback state.
    pub fallback_authorities_sets: HashMap<Round, HashSet<PublicKey>>,

    pub steady_state: bool,
}

impl VirtualState {
    /// Create a new (empty) virtual state.
    pub fn new(committee: Committee, genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            committee: committee.clone(),
            dag: [(0, genesis)].iter().cloned().collect(),
            steady_authorities_sets: [(1, committee.authorities.keys().cloned().collect())]
                .iter()
                .cloned()
                .collect(),
            fallback_authorities_sets: HashMap::new(),
            steady_state: true,
        }
    }

    /// Try to a certificate to the virtual dag and return its success status.
    pub fn try_add(&mut self, certificate: &Certificate) -> bool {
        let round = certificate.virtual_round();

        // Ensure the certificate contains virtual metadata.
        if certificate.header.metadata.is_none() {
            debug!(
                "Certificate rejected - Missing metadata: cert={{author: {}, round: {}, id: {}, shard: {}}}",
                certificate.header.author,
                certificate.header.round,
                certificate.header.id,
                certificate.header.shard_num
            );
            return false;
        }

        // Ensure the virtual metadata are correct. Particularly, ensure all parents are from the previous
        // round and that one of the parents is from the same author as the certificate.
        let previous_round_certificates: Vec<_> = self
            .dag
            .get(&(round - 1))
            .map_or_else(Vec::default, |x| x.values().map(|(x, _)| x).collect());

        let ok = certificate
            .virtual_parents()
            .iter()
            .all(|x| previous_round_certificates.contains(x));
        //&& self
        //    .dag
        //    .get(&(round - 1))
        //    .map_or_else(|| false, |x| x.contains_key(&certificate.origin()));

        // Add the certificate to the dag.
        if ok {
            self.dag.entry(round).or_insert_with(HashMap::new).insert(
                certificate.origin(),
                (certificate.digest(), certificate.clone()),
            );
        }

        ok
    }

    /// Cleanup the internal state after committing a certificate.
    pub fn cleanup(&mut self, last_committed_round: Round, gc_depth: Round) {
        debug!("CLEANUP IN VIRTUAL_STATE");
        // Keep DAG entries as before
        self.dag.retain(|r, _| r + gc_depth > last_committed_round);
        
        // Modified calculations for authority sets with safeguards for round 0
        let min_steady_wave = if last_committed_round > 4 * gc_depth {
            (last_committed_round + 1) / 2 - 4 * gc_depth
        } else {
            0
        };
        
        let min_fallback_wave = if last_committed_round > 2 * gc_depth {
            (last_committed_round + 3) / 4 - 2 * gc_depth
        } else {
            0
        };
        
        self.steady_authorities_sets
            .retain(|w, _| *w >= min_steady_wave);
    
        self.fallback_authorities_sets
            .retain(|w, _| *w >= min_fallback_wave);
            
        debug!(
            "Virtual State Cleanup: last_committed_round={}, gc_depth={}\n\
             ├─ Min steady wave kept: {}\n\
             └─ Min fallback wave kept: {}",
            last_committed_round,
            gc_depth,
            min_steady_wave,
            min_fallback_wave
        );
    }

    /// Returns the certificate (and the certificate's digest) originated by the steady-state leader
    /// of the specified round (if any).
    pub fn steady_leader(&self, wave: Round) -> Option<&(Digest, Certificate)> {

        let seed = wave;

        // Elect the leader.
        let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
        keys.sort();
        let leader = keys[seed as usize % self.committee.size()];

        // Return its certificate and the certificate's digest.
        let round = match wave {
            0 => 0,
            _ => wave * 2 - 1,
        };

        debug!("Supposed leader (Steady): {}, round: {}",self.committee.get_primary_id(&leader),round);
        self.dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Returns the certificate (and the certificate's digest) originated by the fallback leader
    /// of the specified round (if any).
    pub fn fallback_leader(&self, wave: Round) -> Option<&(Digest, Certificate)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.

        let mut hasher = Sha256::new();
        hasher.update(wave.to_le_bytes());
        let result = hasher.finalize();
        let coin = u64::from_le_bytes(result[..8].try_into().unwrap());

        // Elect the leader.
        let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
        keys.sort();
        let leader = keys[coin as usize % self.committee.size()];

        // Return its certificate and the certificate's digest.
        // let round = match wave {
        //     0 => 0,
        //     _ => 1 + (wave-1) *4 ,
        // };

        let round = match wave {
            0 => 0,
            _ => wave*4 -3 ,
        };

        debug!("Supposed leader (Fallback): {}, round: {}",self.committee.get_primary_id(&leader),round);
        
        self.dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Print the mode and latest waves of each authority.
    /// these are based off the last cert of those nodes?
/// Print the mode and latest waves of each authority.
pub fn print_status(&self, certificate: &Certificate) {
    let mut seen = HashSet::new();
    let steady_wave = (certificate.virtual_round() + 1) / 2;
    
    debug!("\n=== Authority Status Summary ===");
    debug!(
        "Certificate Details:\n\
         ├─ ID: {}\n\
         ├─ Primary ID: {}\n\
         ├─ Round: {}\n\
         └─ Steady Wave: {}",
        certificate.header.id,
        self.committee.get_all_primary_ids()[&certificate.origin()],
        certificate.virtual_round(),
        steady_wave
    );

    debug!("\n=== Steady State Authorities ===");
    for w in (1..=steady_wave).rev() {
        if let Some(nodes) = self.steady_authorities_sets.get(&w) {
            for node in nodes {
                if seen.insert(node) {
                    debug!(
                        "Authority:\n\
                         ├─ Primary ID: {}\n\
                         └─ Latest Steady Wave: {}",
                        self.committee.get_all_primary_ids()[node],
                        w
                    );
                }
            }
        }
        if seen.len() == self.committee.size() {
            break;
        }
    }

    seen.clear();
    let fallback_wave = (certificate.virtual_round() + 1) / 4;
    
    debug!("\n=== Fallback State Authorities ===");
    for w in (1..=fallback_wave).rev() {
        if let Some(nodes) = self.fallback_authorities_sets.get(&w) {
            for node in nodes {
                if seen.insert(node) {
                    debug!(
                        "Authority:\n\
                         ├─ Primary ID: {}\n\
                         └─ Latest Fallback Wave: {}",
                        self.committee.get_all_primary_ids()[node],
                        w
                    );
                }
            }
        }
        if seen.len() == self.committee.size() {
            break;
        }
    }

    // Print authorities with no state records
    debug!("\n=== Authorities Without State Records ===");
    let all_authorities: HashSet<_> = self.committee.authorities.keys().collect();
    let steady_authorities: HashSet<_> = self.steady_authorities_sets
        .values()
        .flat_map(|set| set.iter())
        .collect();
    let fallback_authorities: HashSet<_> = self.fallback_authorities_sets
        .values()
        .flat_map(|set| set.iter())
        .collect();
    
    for authority in all_authorities.difference(&steady_authorities) {
        if !fallback_authorities.contains(authority) {
            debug!(
                "Authority:\n\
                 ├─ Primary ID: {}\n\
                 └─ Status: No State Records",
                self.committee.get_all_primary_ids()[authority]
            );
        }
    }
    
    debug!("=====================================\n");
}





}
