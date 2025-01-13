// Copyright(C) Facebook, Inc. and its affiliates.
use crypto::{Digest, Hash as _, PublicKey};
use log::debug;
use primary::{Certificate, Round};
use std::cmp::max;
use std::collections::{HashMap, HashSet};

/// The representation of the DAG in memory.
pub type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
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
        }
    }


    // for debugging. 
    pub fn print_state(&self,mapping:HashMap<PublicKey,u64>) {
        debug!("Last Committed Round: {}", self.last_committed_round);
        
        debug!("Last Committed by Authority:");
        for (authority, round) in &self.last_committed {
            let name = mapping.get(authority);
            debug!("└─ Primary: {} -> Round {}", name.unwrap(), round);
        }
        
        debug!("DAG Structure:");
        // Create a sorted vector of rounds
        let mut rounds: Vec<_> = self.dag.keys().collect();
        rounds.sort(); // Sort rounds in ascending order

        // Iterate over sorted rounds
        for round in rounds {
            if let Some(authorities) = self.dag.get(round) {
                debug!("Round {}:", round);
                for (auth_key, (digest, cert)) in authorities {
                    let name = mapping.get(auth_key);
                    debug!("├─ Primary: {}", name.unwrap());
                    debug!("│  ├─ Digest: {:?}", digest);
                    debug!("│  ├─ Certificate Round: {}", cert.round());
                    debug!("│  ├─ Shard: {}", cert.header.shard_num);
                    debug!("│  └─ Parents:");
                    for parent in &cert.header.parents 
                    {
                        if let Some(prev_round) = self.dag.get(&(cert.round() - 1)) {
                            let parent_info = prev_round.iter()
                                .find(|(_, (digest, _))| digest == parent);
                            
                            match parent_info {
                                Some((auth, (_, parent_cert))) => {
                                    let auth_id = mapping.get(auth).copied().unwrap_or(0);
                                    debug!("│     └─ {:?} (from Primary {}, Shard {})", 
                                        parent, 
                                        auth_id,
                                        parent_cert.header.shard_num
                                    );
                                },
                                // NOTE: usually the below happens when the info has been GC-ed
                                None => debug!("│     └─ {:?} (authority unknown)", parent),
                            }
                        } else {
                            debug!("│     └─ {:?} (round not available)", parent);
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
    pub fn update(&mut self, certificate: &Certificate) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

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
