#!/usr/bin/env python3

import sys
import re
from datetime import datetime
from glob import glob
from os.path import join

def to_posix(string):
    x = datetime.fromisoformat(string.replace('Z', '+00:00'))
    return datetime.timestamp(x)

def analyze_delay_commit_times(log_content):
    # Regex patterns to match the log entries
    committed_pattern = r'\[([^\]]+Z)[^\]]*\] Committed ([^\s]+)'
    early_committed_pattern = r'\[([^\]]+Z)[^\]]*\] Early-Committed ([^\s]+) ->'
    delay_committed_pattern = r'\[([^\]]+Z)[^\]]*\] Delay-Committed ([^\s]+) by ([^\s]+)'
    
    # Find all matches
    committed_matches = re.findall(committed_pattern, log_content)
    early_committed_matches = re.findall(early_committed_pattern, log_content)
    delay_committed_matches = re.findall(delay_committed_pattern, log_content)
    
    # Create dictionaries for easier lookup
    committed_times = {}
    early_committed_times = {}
    delay_committed_data = {}
    
    # Parse committed times
    for timestamp_str, cert_id in committed_matches:
        timestamp = to_posix(timestamp_str)
        committed_times[cert_id] = timestamp
    
    # Parse early-committed times
    for timestamp_str, cert_id in early_committed_matches:
        timestamp = to_posix(timestamp_str)
        early_committed_times[cert_id] = timestamp
    
    # Parse delay-committed times
    for timestamp_str, delayed_cert_id, trigger_cert_id in delay_committed_matches:
        timestamp = to_posix(timestamp_str)
        delay_committed_data[delayed_cert_id] = (timestamp, trigger_cert_id)
    
    # Find pairs and calculate differences
    delays = []
    pairs_found = 0
    
    print("\nDelay-Commit Analysis:")
    print("=" * 80)
    
    for delayed_cert_id, (delay_committed_time, trigger_cert_id) in delay_committed_data.items():
        # First, find when the delayed certificate was originally committed
        original_commit_time = committed_times.get(delayed_cert_id)
        
        if original_commit_time is None:
            print(f"Delayed Certificate {delayed_cert_id}: No original Committed entry found, skipping")
            continue
        
        # Find when the trigger certificate was committed (prefer Early-committed)
        trigger_time = None
        trigger_type = None
        
        if trigger_cert_id in early_committed_times:
            trigger_time = early_committed_times[trigger_cert_id]
            trigger_type = "Early-committed"
        elif trigger_cert_id in committed_times:
            trigger_time = committed_times[trigger_cert_id]
            trigger_type = "Committed"
        
        if trigger_time is not None:
            # Calculate delay: Time B - Time A (trigger time - original commit time)
            delay_ms = (trigger_time - original_commit_time) * 1000
            delays.append(delay_ms)
            pairs_found += 1
            
            print(f"Certificate {delayed_cert_id}:")
            print(f"  Originally Committed:     {datetime.fromtimestamp(original_commit_time).strftime('%H:%M:%S.%f')[:-3]} (Time A)")
            print(f"  Trigger {trigger_cert_id} ({trigger_type}): {datetime.fromtimestamp(trigger_time).strftime('%H:%M:%S.%f')[:-3]} (Time B)")
            print(f"  Delay-Committed:          {datetime.fromtimestamp(delay_committed_time).strftime('%H:%M:%S.%f')[:-3]} (Time C)")
            print(f"  Delay (B-A):              {delay_ms:.3f} ms")
            print()
        else:
            # Fallback: use delay-commit time - original commit time (C-A)
            fallback_delay_ms = (delay_committed_time - original_commit_time) * 1000
            delays.append(fallback_delay_ms)
            pairs_found += 1
            
            print(f"Certificate {delayed_cert_id}:")
            print(f"  Originally Committed:     {datetime.fromtimestamp(original_commit_time).strftime('%H:%M:%S.%f')[:-3]} (Time A)")
            print(f"  Trigger {trigger_cert_id}: NO ENTRY FOUND")
            print(f"  Delay-Committed:          {datetime.fromtimestamp(delay_committed_time).strftime('%H:%M:%S.%f')[:-3]} (Time C)")
            print(f"  Delay (C-A):              {fallback_delay_ms:.3f} ms")
            print()
    
    if delays:
        average_delay = sum(delays) / len(delays)
        print(f"Summary:")
        print(f"  Pairs found: {pairs_found}")
        print(f"  Average delay: {average_delay:.3f} ms")
        print(f"  Min delay: {min(delays):.3f} ms")
        print(f"  Max delay: {max(delays):.3f} ms")
        
        # Additional statistics
        if len(delays) > 1:
            delays_sorted = sorted(delays)
            median_delay = delays_sorted[len(delays) // 2]
            print(f"  Median delay: {median_delay:.3f} ms")
        
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
    log_files = sorted(glob(join(directory_path, 'primary-*.log')))
    
    if not log_files:
        print(f"No primary-*.log files found in {directory_path}")
        sys.exit(1)
    
    for filename in log_files:
        print(f"Reading {filename}")
        with open(filename, 'r') as f:
            all_log_content += f.read() + "\n"
    
    # Analyze delay commits
    analyze_delay_commit_times(all_log_content)

if __name__ == "__main__":
    main()