from datetime import datetime
import os
import sys

#usage:
#python check_primary_logs.py <highest_primary_number> <mode>

def parse_timestamp(timestamp_str):
    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")

def extract_commit_info(line):
    parts = line.split('->')
    batch_info = parts[0].split('B')[1].split(')')[0]
    commit_info = parts[1].strip()
    return batch_info, commit_info

def check_commit_times(log_file_path):
    early_commits = {}
    commits = {}
    
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                if 'Early-Committed B' in line or 'Committed B' in line:
                    timestamp_str = line[1:line.find('Z')+1]
                    timestamp = parse_timestamp(timestamp_str)
                    batch_info, commit_info = extract_commit_info(line)
                    
                    if 'Early-Committed B' in line:
                        if batch_info not in early_commits:
                            early_commits[batch_info] = [(timestamp, commit_info, line.strip())]
                        else:
                            early_commits[batch_info].append((timestamp, commit_info, line.strip()))
                    
                    elif 'Committed B' in line:
                        if batch_info not in commits:
                            commits[batch_info] = [(timestamp, commit_info, line.strip())]
                        else:
                            commits[batch_info].append((timestamp, commit_info, line.strip()))
        
        issues = []
        for batch_info in early_commits:
            if batch_info in commits:
                commit_times = [t for t, c, l in commits[batch_info]]
                commit_infos = [c for t, c, l in commits[batch_info]]
                
                for early_time, early_info, early_line in early_commits[batch_info]:
                    if early_info in commit_infos:
                        commit_time = commit_times[commit_infos.index(early_info)]
                        if early_time > commit_time:
                            issues.append({
                                'type': 'earliest_violation',
                                'batch': batch_info,
                                'early_time': early_time,
                                'commit_time': commit_time,
                                'early_line': early_line
                            })
                    else:
                        issues.append({
                            'type': 'any_violation',
                            'batch': batch_info,
                            'early_time': early_time,
                            'commit_time': None,
                            'early_line': early_line
                        })
        
        duplicate_early_commits = {k: v for k, v in early_commits.items() if len(v) > 1}
        duplicate_issues = []
        for batch_info, times in duplicate_early_commits.items():
            lines = [l for t, c, l in times]
            unique_lines = list(set(lines))
            if len(unique_lines) > 1:  # Only consider them as duplicates if the lines are exactly the same
                continue
            timestamps = [t for t, c, l in times]
            duplicate_issues.append({
                'batch': batch_info,
                'count': len(times),
                'earliest': min(timestamps),
                'latest': max(timestamps),
                'line': unique_lines[0]
            })
        
        return issues, duplicate_issues
    except FileNotFoundError:
        print(f"Warning: File {log_file_path} not found")
        return [], []

def analyze_primary_logs(range_end, mode):
    print(f"Analyzing primary logs from 0 to {range_end}...")
    print("=" * 80)
    
    earliest_violations = []
    any_violations = []
    duplicate_early_commits = []
    
    for i in range(range_end + 1):
        log_file = f"primary-{i}.log"
        print(f"\nChecking {log_file}...")
        
        issues, duplicates = check_commit_times(log_file)
        
        if mode == 1:
            for issue in issues:
                if issue['type'] == 'earliest_violation':
                    earliest_violations.append((i, issue))
                elif issue['type'] == 'any_violation':
                    any_violations.append((i, issue))
        
        for duplicate in duplicates:
            duplicate_early_commits.append((i, duplicate))
    
    if mode == 1:
        print("\n" + "=" * 80)
        print("ANALYSIS RESULTS")
        print("=" * 80)
        
        if earliest_violations:
            print("\nEARLIEST EARLY-COMMIT VIOLATIONS:")
            print("-" * 50)
            for primary_num, violation in earliest_violations:
                print(f"Primary {primary_num}, Batch {violation['batch']}:")
                print(f"  {violation['early_line']}")
                print(f"  Earliest early-commit: {violation['early_time']}")
                print(f"  Regular commit:        {violation['commit_time']}")
                print(f"  Time difference:       {(violation['early_time'] - violation['commit_time']).total_seconds():.3f} seconds")
                print()
        
        if any_violations:
            print("\nANY EARLY-COMMIT VIOLATIONS:")
            print("-" * 50)
            for primary_num, violation in any_violations:
                print(f"Primary {primary_num}, Batch {violation['batch']}:")
                print(f"  {violation['early_line']}")
                print(f"  Violating early-commit: {violation['early_time']}")
                print(f"  Regular commit:         {violation['commit_time']}")
                if violation['commit_time']:
                    print(f"  Time difference:        {(violation['early_time'] - violation['commit_time']).total_seconds():.3f} seconds")
                print()
        
        if duplicate_early_commits:
            print("\nDUPLICATE EARLY COMMITS:")
            print("-" * 50)
            for primary_num, duplicate in duplicate_early_commits:
                print(f"Primary {primary_num}, Batch {duplicate['batch']}:")
                print(f"  {duplicate['line']}")
                print(f"  Number of duplicates:   {duplicate['count']}")
                print(f"  Earliest duplicate:     {duplicate['earliest']}")
                print(f"  Latest duplicate:       {duplicate['latest']}")
                print(f"  Time range:             {(duplicate['latest'] - duplicate['earliest']).total_seconds():.3f} seconds")
                print()
        
        if not earliest_violations and not any_violations and not duplicate_early_commits:
            print("\nNo timing violations or duplicate early commits found in any primary log.")
    else:  # mode == 0
        print("\n" + "=" * 80)
        print("DUPLICATE INSTANCES SUMMARY")
        print("=" * 80)
        
        total_violations = any_violations_count = 0
        
        if duplicate_early_commits:
            total_duplicates = sum([dup['count'] for _, dup in duplicate_early_commits])
            max_duplicates = max([dup['count'] for _, dup in duplicate_early_commits])
            largest_range = max([(dup['latest'] - dup['earliest']).total_seconds() for _, dup in duplicate_early_commits])
            print(f"Total duplicate instances: {len(duplicate_early_commits)}")
            print(f"Largest number of duplicates: {max_duplicates}")
            print(f"Largest range of duplicates (seconds): {largest_range:.3f}")
        else:
            print("No duplicate early commits found.")
        
        for primary_num, violation in earliest_violations:
            total_violations += 1
            if violation['type'] == 'any_violation':
                any_violations_count += 1
        
        print(f"Total early-commit violations: {total_violations}")
        print(f"Total any early-commit violations: {any_violations_count}")
    
    print("\nSUMMARY:")
    print(f"Total files checked: {range_end + 1}")
    if mode == 1:
        print(f"Files with earliest early-commit violations: {len(set(x[0] for x in earliest_violations))}")
        print(f"Files with any early-commit violations: {len(set(x[0] for x in any_violations))}")
    print(f"Files with duplicate early commits: {len(set(x[0] for x in duplicate_early_commits))}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python check_primary_logs.py <highest_primary_number> <mode>")
        print("Mode: 0 = summary, 1 = detailed analysis")
        sys.exit(1)
    
    try:
        range_end = int(sys.argv[1])
        mode = int(sys.argv[2])
        if mode not in [0, 1]:
            raise ValueError("Mode must be 0 or 1")
        analyze_primary_logs(range_end, mode)
    except ValueError as e:
        print(e)
        sys.exit(1)