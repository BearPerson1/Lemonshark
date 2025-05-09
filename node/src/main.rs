// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use config::Export as _;
use config::Import as _;
use config::{Committee, KeyPair, Parameters, WorkerId};
#[cfg(feature = "dolphin")]
use consensus::Dolphin;
#[cfg(not(feature = "dolphin"))]
use consensus::Tusk;
use env_logger::Env;
use primary::{Certificate, Primary};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver};
use worker::Worker;

use log::{debug, error, warn};
use network::ReliableSender;
use bytes::Bytes;
use primary::ClientMessage;

/// The default channel capacity.
pub const CHANNEL_CAPACITY: usize = 1_000;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Narwhal and Tusk.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run a node")
                .args_from_usage("--keys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .subcommand(SubCommand::with_name("primary").about("Run a single primary"))
                .subcommand(
                    SubCommand::with_name("worker")
                        .about("Run a single worker")
                        .args_from_usage("--id=<INT> 'The worker id'"),
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    #[cfg(feature = "benchmark")]
    logger.format_timestamp_millis();
    logger.init();

    match matches.subcommand() {
        ("generate_keys", Some(sub_matches)) => KeyPair::new()
            .export(sub_matches.value_of("filename").unwrap())
            .context("Failed to generate key pair")?,
        ("run", Some(sub_matches)) => run(sub_matches).await?,
        _ => unreachable!(),
    }
    Ok(())
}

// Runs either a worker or a primary.
async fn run(matches: &ArgMatches<'_>) -> Result<()> {
    let key_file = matches.value_of("keys").unwrap();
    let committee_file = matches.value_of("committee").unwrap();
    let parameters_file = matches.value_of("parameters");
    let store_path = matches.value_of("store").unwrap();

    // Read the committee and node's keypair from file.
    let keypair = KeyPair::import(key_file).context("Failed to load the node's keypair")?;
    let committee =
        Committee::import(committee_file).context("Failed to load the committee information")?;

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    // Make the data store.
    let store = Store::new(store_path).context("Failed to create a store")?;

    // Channels the sequence of certificates.
    let (tx_output, rx_output) = channel(CHANNEL_CAPACITY);

    // Check whether to run a primary, a worker, or an entire authority.
    match matches.subcommand() {
        // Spawn the primary and consensus core.
        ("primary", _) => {
            let (tx_new_certificates, rx_new_certificates) = channel(CHANNEL_CAPACITY);
            let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);
            let (tx_metadata, rx_metadata) = channel(CHANNEL_CAPACITY);
            let (tx_client_messages, mut rx_client_messages) = channel::<ClientMessage>(CHANNEL_CAPACITY);

            #[cfg(not(feature = "dolphin"))]
            {
                Tusk::spawn(
                    committee.clone(),
                    parameters.gc_depth,
                    /* rx_primary */ rx_new_certificates,
                    tx_commit,
                    tx_output,
                );
                let _not_used = tx_metadata;
            }

            let mut client_address = match committee.primary_to_client(&keypair.name) {
                Ok(addr) => addr,
                Err(e) => {
                    error!("Failed to get client address: {}", e);
                    return Ok(());
                }
            };
            debug!("Primary to client address: {}", client_address);
    
            // lemonshark - now using ReliableSender
            tokio::spawn(async move {
                let mut client_sender = ReliableSender::new();
                
                while let Some(message) = rx_client_messages.recv().await {
                    let msg = bincode::serialize(&message).unwrap_or_default();
                    let cancel_handler = client_sender.send(client_address, Bytes::from(msg)).await;
                    
                    // Handle acknowledgment with timeout
                    tokio::spawn(async move {
                        match tokio::time::timeout(std::time::Duration::from_secs(5), cancel_handler).await {
                            Ok(Ok(_)) => debug!(
                                "Successfully delivered message to client:\n\
                                ├─ Message Type: {}\n\
                                ├─ Round: {}\n\
                                ├─ Author: {}\n\
                                └─ To Address: {}",
                                if message.message_type == 0 { "Header" } else { "Certificate" },
                                message.header.round,
                                message.header.author,
                                client_address
                            ),
                            Ok(Err(e)) => warn!("Failed to deliver message to client: {:?}", e),
                            Err(_) => warn!("Message delivery to client timed out"),
                        }
                    });
                }
            });

            #[cfg(feature = "dolphin")]
            Dolphin::spawn(
                committee.clone(),
                parameters.timeout,
                parameters.gc_depth,
                /* rx_primary */ rx_new_certificates,
                tx_commit,
                tx_metadata,
                tx_output,
                parameters.cross_shard_occurance_rate,
                parameters.cross_shard_failure_rate,
                parameters.causal_transactions_collision_rate,
                parameters.causal_transactions_respect_early_finality,
                tx_client_messages.clone(),
                keypair.name,
                parameters.cert_timeout,
            );

            Primary::spawn(
                keypair,
                committee,
                parameters.clone(),
                store,
                /* tx_output */ tx_new_certificates,
                rx_commit,
                rx_metadata,
                tx_client_messages,
            );
        }

        // Spawn a single worker.
        ("worker", Some(sub_matches)) => {
            let id = sub_matches
                .value_of("id")
                .unwrap()
                .parse::<WorkerId>()
                .context("The worker id must be a positive integer")?;
            Worker::spawn(keypair.name, id, committee, parameters, store);
        }
        _ => unreachable!(),
    }

    // Analyze the consensus' output.
    analyze(rx_output).await;

    // If this expression is reached, the program ends and all other tasks terminate.
    unreachable!();
}

/// Receives an ordered list of certificates and apply any application-specific logic.
async fn analyze(mut rx_output: Receiver<Certificate>) {
    while let Some(_certificate) = rx_output.recv().await {
        // NOTE: Here goes the application logic.
    }
}