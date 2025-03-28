# Copyright(C) Facebook, Inc. and its affiliates.
import sys
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean
import numpy as np
import matplotlib.pyplot as plt

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, primaries, workers, faults=0):
        inputs = [clients, primaries, workers]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(primaries) + int(faults)
            self.workers = len(workers) // len(primaries)
        else:
            self.committee_size = '?'
            self.workers = '?'

        # Parse the clients logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_clients, clients)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse clients\' logs: {e}')
        self.size, self.rate, self.start, misses, self.sent_samples, \
            self.cc_start, self.cc_end = zip(*results)
        self.misses = sum(misses)

        # Parse the primaries logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_primaries, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse nodes\' logs: {e}')
        proposals, commits, early_commits, self.configs, primary_ips = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])
        self.early_commits = self._merge_results([x.items() for x in early_commits])

        # Parse the workers logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_workers, workers)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse workers\' logs: {e}')
        sizes, self.received_samples, workers_ips = zip(*results)
        self.sizes = {
            k: v for x in sizes for k, v in x.items() if k in self.commits
        }

        # Determine whether the primary and the workers are collocated.
        self.collocate = set(primary_ips) == set(workers_ips)

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        size = int(search(r'Transactions size: (\d+)', log).group(1))
        rate = int(search(r'Transactions rate: (\d+)', log).group(1))

        tmp = search(r'\[(.*Z) .* Start ', log).group(1)
        start = self._to_posix(tmp)

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
        samples = {int(s): self._to_posix(t) for t, s in tmp}

        # lemonshark: causal transactions:
        cc_start_tmp = findall(r'\[(.*Z) .* Sending causal-transaction (\d+)', log)
        cc_start = {int(s): self._to_posix(t) for t, s in cc_start_tmp}

        cc_end_tmp = findall(r'\[(.*Z) .* Finalizing causal-transaction (\d+)', log)
        cc_end = {int(s): self._to_posix(t) for t, s in cc_end_tmp}

        return size, rate, start, misses, samples, cc_start, cc_end

    def _parse_primaries(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise ParseError('Primary(s) panicked')

        tmp = findall(r'\[(.*Z) .* Created B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[(.*Z) .* Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        # Lemonshark
        tmp = findall(r'\[(.*Z) .* Early-Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        early_commits = self._merge_results([tmp])

        # Some assertions for lemonshark
        for digest in early_commits:
            if digest in commits:
                assert early_commits[digest] <= commits[digest], \
                    f"Early commit time ({early_commits[digest]}) is after regular commit time ({commits[digest]}) for digest {digest}"

        configs = {
            'header_size': int(
                search(r'Header size .* (\d+)', log).group(1)
            ),
            'max_header_delay': int(
                search(r'Max header delay .* (\d+)', log).group(1)
            ),
            'gc_depth': int(
                search(r'Garbage collection depth .* (\d+)', log).group(1)
            ),
            'sync_retry_delay': int(
                search(r'Sync retry delay .* (\d+)', log).group(1)
            ),
            'sync_retry_nodes': int(
                search(r'Sync retry nodes .* (\d+)', log).group(1)
            ),
            'batch_size': int(
                search(r'Batch size .* (\d+)', log).group(1)
            ),
            'max_batch_delay': int(
                search(r'Max batch delay .* (\d+)', log).group(1)
            ),
        }

        ip = search(r'booted on (\d+\.\d+\.\d+\.\d+)', log).group(1)

        return proposals, commits, early_commits, configs, ip

    def _parse_workers(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise ParseError('Worker(s) panicked')

        tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
        samples = {int(s): d for d, s in tmp}

        ip = search(r'booted on (\d+\.\d+\.\d+\.\d+)', log).group(1)

        return sizes, samples, ip

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _consensus_throughput(self):
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.proposals.values()), max(self.commits.values())
        duration = end - start
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [c - self.proposals[d] for d, c in self.commits.items()]
        self.plot_cons_latencies(latency)
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.start), max(self.commits.values())
        duration = end - start
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration



    def _end_to_end_latency(self):
        latency = []
        # Create a list to store all transaction details with timestamps
        transaction_details = []
        
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                if batch_id in self.commits:
                    assert tx_id in sent
                    start = sent[tx_id]
                    end = self.commits[batch_id]
                    latency_value = end - start
                    latency.append(latency_value)

                    # Store transaction details with timestamp
                    transaction_details.append({
                        'tx_number': tx_id,
                        'batch_id': batch_id,
                        'start_time': start,
                        'latency': latency_value
                    })

        # Sort transaction details by start time
        transaction_details.sort(key=lambda x: x['start_time'])

        # Write to file with timestamps
        with open('transaction_details.txt', 'w') as f:
            # Write header
            f.write(f"{'Txn Number':<12} | {'Batch ID':<40} | {'Start Time (s)':<15} | {'Latency (s)':<10}\n")
            f.write("-" * 82 + "\n")
            
            # Write data
            first_timestamp = transaction_details[0]['start_time'] if transaction_details else 0
            for detail in transaction_details:
                relative_time = detail['start_time'] - first_timestamp
                f.write(f"{detail['tx_number']:<12} | {detail['batch_id']:<40} | {relative_time:15.3f} | {detail['latency']:.4f}\n")

        if latency:
            latency_array = np.array(latency)
            
            plt.figure(figsize=(10, 6))
            plt.hist(latency_array, bins=50, alpha=0.75, color='blue', edgecolor='black')
            plt.title('End-to-End Latency Distribution')
            plt.xlabel('Latency (seconds)')
            plt.ylabel('Frequency')
            plt.grid(True)
            plt.savefig('end_to_end_latency_distribution.png')
            plt.close()

            # Create time-based latency plot
            if transaction_details:
                plt.figure(figsize=(12, 6))
                
                # Extract timestamps and normalize them to start from 0
                start_times = [d['start_time'] for d in transaction_details]
                latencies = [d['latency'] for d in transaction_details]
                
                # Normalize timestamps to start from 0
                start_time = start_times[0]
                normalized_times = [t - start_time for t in start_times]
                
                plt.plot(normalized_times, latencies, '-o', markersize=3, alpha=0.6)
                plt.title('End-to-End Latency Over Time')
                plt.xlabel('Time (seconds)')
                plt.ylabel('Latency (seconds)')
                plt.grid(True, alpha=0.3)
                
                avg_latency = np.mean(latencies)
                plt.axhline(y=avg_latency, color='r', linestyle='--', alpha=0.5,
                        label=f'Average Latency: {avg_latency:.2f}s')
                
                plt.legend()
                plt.tight_layout()
                plt.savefig('transaction_latencies.png')
                plt.close()
            
        return mean(latency) if latency else 0

    ## lemonshark
    
    def _early_consensus_latency(self):
        latency = []
        for digest in set(self.commits.keys()) | set(self.early_commits.keys()):
            if digest in self.proposals:
                proposal_time = self.proposals[digest]
                
                # Initialize with regular commit time if it exists
                commit_time = self.commits.get(digest, float('inf'))
                
                if digest in self.early_commits:
                    # Skip if digest is in early_commits but not in commits
                    if digest not in self.commits:
                        continue
                    early_commit_time = self.early_commits[digest]
                    commit_time = min(commit_time, early_commit_time)
                
                # Only add if we found a valid commit (regular or early)
                if commit_time != float('inf'):
                    latency.append(commit_time - proposal_time)
        
        return mean(latency) if latency else 0

    def _early_end_to_end_latency(self):
        latency = []
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                # Check if transaction exists in either commit type
                commit_time = float('inf')
                
                if batch_id in self.commits:
                    commit_time = self.commits[batch_id]
                
                if batch_id in self.early_commits:
                    # Skip if batch_id is in early_commits but not in commits
                    if batch_id not in self.commits:
                        continue
                    early_commit_time = self.early_commits[batch_id]
                    commit_time = min(commit_time, early_commit_time)
                
                # Only calculate latency if commit_time is updated
                if commit_time != float('inf'):
                    assert tx_id in sent  # We receive txs that we sent.
                    start = sent[tx_id]
                    latency_value = commit_time - start
                    latency.append(latency_value)
                    # print(f"Batch ID: {batch_id}, Latency: {latency_value} seconds")
        
        return mean(latency) if latency else 0

    ## Lemonshark
    def get_causal_transaction_duration(self):
        import os
        from matplotlib import pyplot as plt
        import numpy as np
        
        # Create CC-plots directory if it doesn't exist
        os.makedirs('CC-plots', exist_ok=True)
        
        per_tx_times = []
        has_incomplete = False
        
        # Loop through all clients
        for client_index in range(len(self.cc_start)):
            # First check for incomplete transactions
            for tx_id in self.cc_start[client_index].keys():
                if tx_id not in self.cc_end[client_index]:
                    has_incomplete = True
                    break
            
            # Calculate and plot times for this client
            if self.cc_start[client_index] and self.cc_end[client_index]:
                # Get all transaction IDs that completed
                tx_ids = sorted([tx_id for tx_id in self.cc_start[client_index].keys() 
                            if tx_id in self.cc_end[client_index]])
                
                if not tx_ids:  # Skip if no transactions
                    continue

                # Calculate durations for plotting
                durations = []
                for tx_id in tx_ids:
                    start_time = self.cc_start[client_index][tx_id]
                    end_time = self.cc_end[client_index][tx_id]
                    duration = end_time - start_time
                    durations.append(duration)
                
                # New average calculation
                first_tx_start = self.cc_start[client_index][tx_ids[0]]  # First transaction start
                last_tx_end = self.cc_end[client_index][tx_ids[-1]]      # Last transaction end
                total_time = last_tx_end - first_tx_start                # Total time
                num_transactions = tx_ids[-1]  # Use the last transaction ID as the count
                avg_duration = total_time / num_transactions if num_transactions > 0 else 0
                
                per_tx_times.append(avg_duration)
                
                # Create the plot
                plt.figure(figsize=(12, 6))
                plt.plot(tx_ids, durations, '-o', markersize=3, alpha=0.6)
                plt.title(f'Causal Transaction Durations - Client {client_index}')
                plt.xlabel('Transaction ID')
                plt.ylabel('Duration (seconds)')
                plt.grid(True, alpha=0.3)
                
                # Add average line using the new calculation method
                plt.axhline(y=avg_duration, color='r', linestyle='--', alpha=0.5,
                        label=f'Average Duration: {avg_duration:.3f}s')
                
                plt.legend()
                plt.tight_layout()
                
                # Save the plot
                plt.savefig(f'CC-plots/client_{client_index}_durations.png')
                plt.close()
                
                print(f"\nClient {client_index} Analysis:")
                print(f"  - Total transactions started: {len(self.cc_start[client_index])}")
                print(f"  - Total transactions completed: {len(self.cc_end[client_index])}")
                print(f"  - First transaction start time: {first_tx_start}")
                print(f"  - Last transaction end time: {last_tx_end}")
                print(f"  - Total time: {total_time:.3f}s")
                print(f"  - Number of transactions (last ID): {num_transactions}")
                print(f"  - Average duration: {avg_duration:.3f}s")
                
        # Return the average time per transaction across all clients and incomplete status
        return mean(per_tx_times) if per_tx_times else 0, has_incomplete

    def plot_transaction_latencies(self, latencies):
        """
        Create a line plot of transaction latencies using actual timestamps.
        """
        # Get transaction timestamps
        timestamps = []
        ordered_latencies = []
        
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                if batch_id in self.commits and tx_id in sent:
                    timestamps.append(sent[tx_id])  # Use the transaction's send time as timestamp
                    start = sent[tx_id]
                    end = self.commits[batch_id]
                    ordered_latencies.append(end - start)
        
        # Sort by timestamp
        if timestamps and ordered_latencies:
            # Create sorted pairs of timestamps and latencies
            sorted_pairs = sorted(zip(timestamps, ordered_latencies))
            timestamps, ordered_latencies = zip(*sorted_pairs)
            
            # Normalize timestamps to start from 0
            start_time = timestamps[0]
            normalized_timestamps = [t - start_time for t in timestamps]
            
            plt.figure(figsize=(12, 6))
            plt.plot(normalized_timestamps, ordered_latencies, '-o', markersize=3, alpha=0.6)
            plt.title('Transaction Latency Over Time')
            plt.xlabel('Time (seconds)')
            plt.ylabel('Latency (seconds)')
            plt.grid(True, alpha=0.3)
            
            avg_latency = np.mean(ordered_latencies)
            plt.axhline(y=avg_latency, color='r', linestyle='--', alpha=0.5,
                    label=f'Average Latency: {avg_latency:.2f}s')
            
            plt.legend()
            plt.tight_layout()
            plt.savefig('transaction_latencies.png')
            plt.close()


    def plot_cons_latencies(self, latencies):
        """
        Create a line plot of consensus latencies using actual timestamps.
        """
        # Get proposal timestamps and corresponding latencies
        timestamps = []
        ordered_latencies = []
        
        for digest, commit_time in self.commits.items():
            if digest in self.proposals:
                proposal_time = self.proposals[digest]
                timestamps.append(proposal_time)  # Use proposal time as timestamp
                ordered_latencies.append(commit_time - proposal_time)
        
        # Sort by timestamp
        if timestamps and ordered_latencies:
            # Create sorted pairs of timestamps and latencies
            sorted_pairs = sorted(zip(timestamps, ordered_latencies))
            timestamps, ordered_latencies = zip(*sorted_pairs)
            
            # Normalize timestamps to start from 0
            start_time = timestamps[0]
            normalized_timestamps = [t - start_time for t in timestamps]
            
            plt.figure(figsize=(12, 6))
            plt.plot(normalized_timestamps, ordered_latencies, '-o', markersize=3, alpha=0.6)
            plt.title('Consensus Latency Over Time')
            plt.xlabel('Time (seconds)')
            plt.ylabel('Latency (seconds)')
            plt.grid(True, alpha=0.3)
            
            avg_latency = np.mean(ordered_latencies)
            plt.axhline(y=avg_latency, color='r', linestyle='--', alpha=0.5,
                    label=f'Average Latency: {avg_latency:.2f}s')
            
            plt.legend()
            plt.tight_layout()
            plt.savefig('cons_latencies.png')
            plt.close()

    def result(self):
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']

        consensus_latency = self._consensus_latency() * 1_000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000

        early_consensus_latency = self._early_consensus_latency() * 1_000
        early_end_to_end_latency = self._early_end_to_end_latency() * 1_000

        # Get causal transaction metrics
        causal_duration, has_incomplete = self.get_causal_transaction_duration()
        causal_duration_ms = causal_duration * 1_000  # Convert to milliseconds

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n'
            '\n'
            ' + RESULTS:\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            '\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            '\n'
            ' + LEMONSHARK METRICS:\n'
            f' EARLY Consensus latency: {round(early_consensus_latency):,} ms\n'
            f' EARLY End-to-end latency: {round(early_end_to_end_latency):,} ms\n'
            '\n'
            f' Average causal transaction latency: {round(causal_duration_ms):,} ms\n'
            f' Has incomplete transactions: {has_incomplete}\n'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, faults=0):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients += [f.read()]
        primaries = []
        for filename in sorted(glob(join(directory, 'primary-*.log'))):
            with open(filename, 'r') as f:
                primaries += [f.read()]
        workers = []
        for filename in sorted(glob(join(directory, 'worker-*.log'))):
            with open(filename, 'r') as f:
                workers += [f.read()]
        return cls(clients, primaries, workers, faults=faults)


if __name__ == "__main__":
    directory = sys.argv[1]
    faults = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    log_parser = LogParser.process(directory, faults=faults)
    print(log_parser.result())