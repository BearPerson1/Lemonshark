#!/usr/bin/env python3

import re
import sys
from datetime import datetime
from typing import Dict, Optional
from collections import Counter

def analyze_log_file(x: str) -> None:
    filename = f"primary-{x}.log"
    # Store the latest header proposal conditions for each round
    proposal_conditions: Dict[int, str] = {}
    
    # Store all found round numbers from Creating new header lines
    rounds = set()
    max_round = 0
    
    # Counter for header proposal conditions per round
    conditions_count = Counter()
    
    # Regex patterns
    header_pattern = re.compile(r'\[.*DEBUG primary::proposer\] Creating new header for \[primary: .*, round: (\d+),')
    conditions_pattern = re.compile(r'(\[.*DEBUG primary::proposer\] Header proposal conditions for round (\d+):.*)')

    try:
        with open(filename, 'r') as file:
            for line in file:
                # Check for new header creation lines
                header_match = header_pattern.search(line)
                if header_match:
                    round_num = int(header_match.group(1))
                    rounds.add(round_num)
                    max_round = max(max_round, round_num)
                
                # Store the latest conditions line for each round and count occurrences
                conditions_match = conditions_pattern.search(line)
                if conditions_match:
                    round_num = int(conditions_match.group(2))
                    proposal_conditions[round_num] = conditions_match.group(1)
                    conditions_count[round_num] += 1

        # Check for missing rounds
        missing_rounds = []
        for round_num in range(1, max_round + 1):
            if round_num not in rounds:
                missing_rounds.append(round_num)

        print(f"\nAnalysis for {filename}:")
        print("=" * 50)
        
        # Print conditions count for all rounds
        print("\nHeader proposal conditions count per round:")
        for round_num in range(1, max_round + 1):
            count = conditions_count[round_num]
            print(f"Round {round_num}: {count} condition{'s' if count != 1 else ''}")

        if missing_rounds:
            print(f"\nMissing rounds detected: {missing_rounds}")
            print("\nLatest proposal conditions for missing rounds:")
            for round_num in missing_rounds:
                if round_num in proposal_conditions:
                    print(f"\nFor round {round_num}:")
                    print(proposal_conditions[round_num])
                else:
                    print(f"\nNo proposal conditions found for round {round_num}")
        else:
            print(f"\nNo missing rounds detected. Rounds found: 1 to {max_round}")

        print("\nSummary:")
        print(f"Total rounds expected: {max_round}")
        print(f"Total rounds found: {len(rounds)}")
        print(f"Total missing rounds: {len(missing_rounds)}")
        print(f"Total header proposal conditions across all rounds: {sum(conditions_count.values())}")

    except FileNotFoundError:
        print(f"Error: Could not find the file '{filename}'")
    except Exception as e:
        print(f"Error occurred while processing the file: {str(e)}")

def print_usage():
    print("Usage: ./check_rounds.py <x>")
    print("Example: ./check_rounds.py 1")
    print("This will analyze primary-1.log")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Missing required argument 'x'")
        print_usage()
        sys.exit(1)

    x = sys.argv[1]
    analyze_log_file(x)