#!/usr/bin/env python3

import re
import sys
import os
from datetime import datetime
from typing import Dict, Optional, Tuple, Set
from collections import Counter, defaultdict

#usage: python3 check_missing_rounds.py ../benchmark/logs


def analyze_log_file(filepath: str) -> Tuple[Set[int], Set[int], int]:
    # Store all found round numbers
    rounds = set()
    max_round = 0
    
    # Regex pattern for header creation
    header_pattern = re.compile(r'\[.*DEBUG primary::proposer\] Creating new header for \[primary: .*, round: (\d+),')

    try:
        with open(filepath, 'r') as file:
            for line in file:
                # Check for new header creation lines
                header_match = header_pattern.search(line)
                if header_match:
                    round_num = int(header_match.group(1))
                    rounds.add(round_num)
                    max_round = max(max_round, round_num)

        # Calculate missing rounds
        missing_rounds = set(range(1, max_round + 1)) - rounds

        return rounds, missing_rounds, max_round

    except Exception as e:
        print(f"Error processing {filepath}: {str(e)}")
        return set(), set(), 0

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
    print(f"\n{'Primary':<10} {'Max Round':<12} {'Total Rounds':<15} {'Missing Rounds':<40}")
    print("-" * 77)

    for log_file in primary_logs:
        filepath = os.path.join(logs_path, log_file)
        primary_num = log_file.replace('primary-', '').replace('.log', '')
        
        rounds, missing_rounds, max_round = analyze_log_file(filepath)
        
        if max_round > 0:  # Only show primaries that have some rounds
            missing_str = f"{len(missing_rounds)} rounds: {sorted(missing_rounds)[:100]}"
            if len(missing_rounds) > 100:
                missing_str += f" ... (+{len(missing_rounds)-100} more)"
                
            print(f"{primary_num:<10} {max_round:<12} {len(rounds):<15} {missing_str:<40}")

def print_usage():
    print("Usage: ./check_rounds.py <logs_directory>")
    print("Example: ./check_rounds.py ../benchmark/logs")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Missing required argument 'logs_directory'")
        print_usage()
        sys.exit(1)

    logs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', sys.argv[1]))
    analyze_directory(logs_path)