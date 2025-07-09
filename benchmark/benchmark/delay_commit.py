#!/usr/bin/env python3

import sys
import re
from datetime import datetime
from glob import glob
from os.path import join
#usage:  python3 delay_commit.py ../logs/
def to_posix(string):
    x = datetime.fromisoformat(string.replace('Z', '+00:00'))
    return datetime.timestamp(x)

def analyze_delay_commit_times(log_content):
    # Regex patterns to match the log entries
    committed_pattern = r'\[([^\]]+Z)[^\]]*\] Committed ([^\s]+)'
    delay_committed_pattern = r'\[([^\]]+Z)[^\]]*\] Delay-Committed ([^\s]+)'
    
    # Find all matches
    committed_matches = re.findall(committed_pattern, log_content)
    delay_committed_matches = re.findall(delay_committed_pattern, log_content)
    
    # Create dictionaries for easier lookup
    committed_times = {}
    delay_committed_times = {}
    
    # Parse committed times
    for timestamp_str, cert_id in committed_matches:
        timestamp = to_posix(timestamp_str)
        committed_times[cert_id] = timestamp
    
    # Parse delay-committed times
    for timestamp_str, cert_id in delay_committed_matches:
        timestamp = to_posix(timestamp_str)
        delay_committed_times[cert_id] = timestamp
    
    # Find pairs and calculate differences
    delays = []
    pairs_found = 0
    
    print("\nDelay-Commit Analysis:")
    print("=" * 60)
    
    for cert_id in delay_committed_times:
        if cert_id in committed_times:
            committed_time = committed_times[cert_id]
            delay_committed_time = delay_committed_times[cert_id]
            
            # Calculate difference in milliseconds
            delay_ms = (delay_committed_time - committed_time) * 1000
            delays.append(delay_ms)
            pairs_found += 1
            
            print(f"Certificate {cert_id}:")
            print(f"  Committed:       {datetime.fromtimestamp(committed_time).strftime('%H:%M:%S.%f')[:-3]}")
            print(f"  Delay-Committed: {datetime.fromtimestamp(delay_committed_time).strftime('%H:%M:%S.%f')[:-3]}")
            print(f"  Delay:           {delay_ms:.3f} ms")
            print()
    
    if delays:
        average_delay = sum(delays) / len(delays)
        print(f"Summary:")
        print(f"  Pairs found: {pairs_found}")
        print(f"  Average delay: {average_delay:.3f} ms")
        print(f"  Min delay: {min(delays):.3f} ms")
        print(f"  Max delay: {max(delays):.3f} ms")
        return average_delay, pairs_found, delays
    else:
        print("No matching pairs found!")
        return 0, 0, []

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_delays.py <log_directory>")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    
    # Read all primary log files
    all_log_content = ""
    for filename in sorted(glob(join(directory_path, 'primary-*.log'))):
        print(f"Reading {filename}")
        with open(filename, 'r') as f:
            all_log_content += f.read() + "\n"
    
    # Analyze delay commits
    analyze_delay_commit_times(all_log_content)

if __name__ == "__main__":
    main()