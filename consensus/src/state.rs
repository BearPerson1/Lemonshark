// Copyright(C) Facebook, Inc. and its affiliates.
use crypto::{Digest, Hash as _, PublicKey};
use log::debug;
use primary::{Certificate, Round};
use std::cmp::max;
use std::collections::{HashMap, HashSet};

/// The representation of the DAG in memory.
pub type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
#[derive(Clone)]
pub struct State {
    /// The garbage collection depth.
    gc_depth: Round,
    /// The last committed round.
    pub last_committed_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    pub last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its children) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    pub dag: Dag,

    pub early_committed_certs: HashSet<Certificate>,
    pub skipped_certs: HashSet<Certificate>,

}

impl State {
    pub fn new(gc_depth: Round, genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();
        Self {
            gc_depth,
            last_committed_round: 0,
            last_committed: genesis.iter().map(|(x, (_, y))| (*x, y.round())).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
            early_committed_certs: HashSet::new(),
            skipped_certs: HashSet::new(),
        }
    }

    /// Clear all certificates from the skip list
    pub fn clear_early_committed_certs(&mut self) {
        // debug!("Clearing skip certificates list");
        self.early_committed_certs.clear();
    }

    pub fn add_early_committed_certs(&mut self, cert: Certificate) {
        // debug!("Adding certificate to early committed list from round {} with digest {:?}", 
        //        cert.round(), 
        //        cert.digest());
        self.early_committed_certs.insert(cert); 
    }

    pub fn remove_early_committed_certs(&mut self, cert: &Certificate) -> bool {
        let removed = self.early_committed_certs.remove(cert); 
        if removed {
            //debug!("Removed certificate from early committed list from round {}", cert.round());
        }
        removed
    }

    // For debugging
    // Note: Its quite verbose
    pub fn print_state(&self, mapping: HashMap<PublicKey, u64>) {
        debug!("Last Committed Round: {}", self.last_committed_round);
        
        debug!("Last Committed by Authority:");
        let mut sorted_authorities: Vec<_> = self.last_committed.iter().collect();
        sorted_authorities.sort_by_key(|(auth, _)| mapping.get(auth).unwrap_or(&u64::MAX));
        for (authority, round) in sorted_authorities {
            let name = mapping.get(authority);
            debug!("└─ Primary: {} -> Round {}", name.unwrap(), round);
        }
        
        debug!("DAG Structure:");
        // Create a sorted vector of rounds
        let mut rounds: Vec<_> = self.dag.keys().collect();
        rounds.sort(); // Sort rounds in ascending order
    
        // Iterate over sorted rounds
        // skip the genesis blocks
        for round in rounds {
            if *round == 0 {
                continue;
            }
            if let Some(authorities) = self.dag.get(round) {
                debug!("Round {}:", round);
                let mut sorted_auth: Vec<_> = authorities.iter().collect();
                sorted_auth.sort_by_key(|(auth_key, _)| mapping.get(auth_key).unwrap_or(&u64::MAX));

                 for (auth_key, (digest, cert)) in sorted_auth {
                    let name = mapping.get(auth_key);
                    debug!("├─ Primary: {}", name.unwrap());
                    //debug!("│  ├─ Digest: {:?}", digest);
                    debug!("│  ├─ Certificate Round: {}", cert.round());
                    debug!("│  ├─ Shard: {}", cert.header.shard_num);
                    if (cert.header.cross_shard!=0)
                    {
                        debug!("│  ├─ Cross-Shard: {}, {}", cert.header.cross_shard,cert.header.early_fail);
                    }
                    debug!("│  └─ Parents:");
                    // For each parent, print its information
                    if cert.header.parents_id_shard.is_empty() {
                        if cert.round() <= 1 {
                            debug!("│     └─ GENESIS");
                        }else {
                            // this might be thrown for round 1. This is expected as "genesis" does not seem to appear as a certicate. 
                            debug!("│     └─ WARNING: No parents exist for this certificate!");
                            debug!("│        └─ Certificate Round: {}, Origin: {}", cert.round(), cert.origin());
                        }
                    } else {
                        let mut sorted_parents: Vec<_> = cert.header.parents_id_shard.iter().collect();
                        sorted_parents.sort_by_key(|(primary_id, _)| *primary_id);
                        // For each parent, print its information
                        for (primary_id, parent_shard) in sorted_parents {
                            debug!("│     └─ Primary: {}, Shard: {}", primary_id, parent_shard);
                        }
                    }
                }
            }
        }
        
        debug!("GC Depth: {}", self.gc_depth);
        debug!("=======================================\n");
    }


    /// Add a certificate to the dag.
    pub fn add(&mut self, certificate: Certificate) {
        self.dag
            .entry(certificate.round())
            .or_insert_with(HashMap::new)
            .insert(certificate.origin(), (certificate.digest(), certificate));
    }

    /// Update and clean up internal state base on committed certificates.
    /// For each authority:
    // It goes through each round in the DAG
    // Removes any certificates from that authority that are from rounds before its last committed round
    // Removes entire rounds if:
    //     They become empty after removing certificates, OR
    //     They are older than last_committed_round - gc_dept
    /// 
    /// 
    pub fn update(&mut self, certificate: &Certificate) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        // TODO remove. 
        // debug!("[UPDATE STATE]: Round: {}, Shard: {}",
        //     certificate.header.round,
        //     certificate.header.shard_num
        // );

        let last_committed_round = *self.last_committed.values().max().unwrap();
        self.last_committed_round = last_committed_round;

        let gc_depth = self.gc_depth;
        for (name, round) in &self.last_committed {
            self.dag.retain(|r, authorities| {
                authorities.retain(|n, _| n != name || r >= round);
                !authorities.is_empty() && r + gc_depth >= last_committed_round
            });
        }
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    pub fn flatten(&self, vertex: &Certificate) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", vertex);
        let mut ordered = Vec::new();
        let mut already_ordered = HashSet::new();

        let mut buffer = vec![vertex];
        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());
            for parent in &x.header.parents {
                let (digest, certificate) = match self
                    .dag
                    .get(&(x.round() - 1))
                    .map(|x| x.values().find(|(x, _)| x == parent))
                    .flatten()
                {
                    Some(x) => x,
                    None => continue, // We already ordered or GC up to here.
                };

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(&digest);
                skip |= self
                    .last_committed
                    .get(&certificate.origin())
                    .map_or_else(|| false, |r| r == &certificate.round());
                if !skip {
                    buffer.push(certificate);
                    already_ordered.insert(digest);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth > self.last_committed_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }
}
