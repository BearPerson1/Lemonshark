#!/usr/bin/env python3

import re
import sys
import os
from datetime import datetime
from typing import Dict, Set, Tuple
from collections import defaultdict

def analyze_log_file(filepath: str) -> Tuple[Set[str], Set[str], Set[str]]:
    # Store processed and virtual certs
    processed_certs = set()
    virtual_certs = set()
    
    # Regex patterns for certificate processing and virtual addition
    process_pattern = re.compile(r'\[.*DEBUG consensus::dolphin::core\] Processing cert ([^:]+): C(\d+)')
    virtual_pattern = re.compile(r'\[.*DEBUG consensus::dolphin::core\] Adding virtual ([^:]+): C(\d+)')

    try:
        with open(filepath, 'r') as file:
            for line in file:
                # Check for processed certificates
                process_match = process_pattern.search(line)
                if process_match:
                    cert_id = process_match.group(1)
                    round_num = process_match.group(2)
                    processed_certs.add((cert_id, round_num))

                # Check for virtual additions
                virtual_match = virtual_pattern.search(line)
                if virtual_match:
                    cert_id = virtual_match.group(1)
                    round_num = virtual_match.group(2)
                    virtual_certs.add((cert_id, round_num))

        # Find missing virtual additions
        missing_virtual = processed_certs - virtual_certs

        return processed_certs, virtual_certs, missing_virtual

    except Exception as e:
        print(f"Error processing {filepath}: {str(e)}")
        return set(), set(), set()

def analyze_directory(logs_path: str) -> None:
    if not os.path.exists(logs_path):
        print(f"Error: Directory '{logs_path}' does not exist")
        return

    print(f"\nAnalyzing logs in: {logs_path}")
    print("=" * 50)
    
    # Find and sort all primary log files
    primary_logs = sorted([f for f in os.listdir(logs_path) if f.startswith('primary-') and f.endswith('.log')])
    
    if not primary_logs:
        print(f"No primary log files found in {logs_path}")
        return

    # Print header
    print(f"\n{'Primary':<10} {'Total Processed':<15} {'Total Virtual':<15} {'Missing Virtual Certs':<50}")
    print("-" * 90)

    for log_file in primary_logs:
        filepath = os.path.join(logs_path, log_file)
        primary_num = log_file.replace('primary-', '').replace('.log', '')
        
        processed, virtual, missing = analyze_log_file(filepath)
        
        if processed:  # Only show primaries that have some certificates
            missing_str = f"{len(missing)} certs: " + ", ".join(f"{cert}(R{round})" for cert, round in sorted(missing)[:5])
            if len(missing) > 5:
                missing_str += f" ... (+{len(missing)-5} more)"
                
            print(f"{primary_num:<10} {len(processed):<15} {len(virtual):<15} {missing_str:<50}")

        # Print detailed missing certificates info
        if missing:
            print("\nDetailed missing virtual additions for primary", primary_num)
            print("-" * 50)
            for cert_id, round_num in sorted(missing):
                print(f"Round {round_num}: Certificate {cert_id}")
            print()

def print_usage():
    print("Usage: ./check_virtual_certs.py <logs_directory>")
    print("Example: ./check_virtual_certs.py ../benchmark/logs")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Missing required argument 'logs_directory'")
        print_usage()
        sys.exit(1)

    logs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', sys.argv[1]))
    analyze_directory(logs_path)