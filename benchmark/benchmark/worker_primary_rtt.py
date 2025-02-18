import os
import re
from datetime import datetime
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class LogAnalyzer:
    def __init__(self, logs_dir):
        self.logs_dir = Path(logs_dir)
        self.worker_pattern = re.compile(r'worker-(\d+)-0\.log')

    def parse_timestamp(self, timestamp_str):
        try:
            # Clean timestamp string - remove Z and everything after it
            clean_ts = timestamp_str.split('Z')[0]
            return datetime.strptime(clean_ts, '%Y-%m-%dT%H:%M:%S.%f')
        except Exception as e:
            print(f"Error parsing timestamp {timestamp_str}: {e}")
            return None

    def process_worker_file(self, file_path, node_number):
        digests = {}  # {digest: latest_timestamp}
        print(f"\nProcessing worker file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if "Batch" in line and "contains" in line:
                        # Extract timestamp
                        timestamp_match = re.match(r'\[(.*?)\]', line)
                        if not timestamp_match:
                            continue
                        timestamp_str = timestamp_match.group(1)
                        timestamp = self.parse_timestamp(timestamp_str)
                        if not timestamp:
                            continue

                        # Extract digest
                        digest_match = re.search(r'Batch\s+([^\s]+)\s+contains', line)
                        if not digest_match:
                            continue
                        digest = digest_match.group(1)

                        # Update digest with latest timestamp
                        if digest not in digests or timestamp > digests[digest]:
                            digests[digest] = timestamp
                
                print(f"Found {len(digests)} unique digests in worker file")
                return digests
                
        except Exception as e:
            print(f"Error reading worker file {file_path}: {e}")
            return {}

    def process_primary_file(self, file_path, node_number):
        digests = {}  # {digest: latest_timestamp}
        print(f"\nProcessing primary file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if "Received Digest:" in line:
                        # Extract timestamp
                        timestamp_match = re.match(r'\[(.*?)\]', line)
                        if not timestamp_match:
                            continue
                        timestamp_str = timestamp_match.group(1)
                        timestamp = self.parse_timestamp(timestamp_str)
                        if not timestamp:
                            continue

                        # Extract digest
                        digest_match = re.search(r'Received Digest:\s+([^\s]+)', line)
                        if not digest_match:
                            continue
                        digest = digest_match.group(1)

                        # Update digest with latest timestamp
                        if digest not in digests or timestamp > digests[digest]:
                            digests[digest] = timestamp
                
                print(f"Found {len(digests)} unique digests in primary file")
                return digests
                
        except Exception as e:
            print(f"Error reading primary file {file_path}: {e}")
            return {}

    def find_log_pairs(self):
        log_pairs = {}
        print(f"\nSearching for log files in: {self.logs_dir}")
        
        try:
            all_files = list(self.logs_dir.iterdir())
            print(f"Files found: {[f.name for f in all_files]}")
            
            for file in all_files:
                if match := self.worker_pattern.match(file.name):
                    node_num = int(match.group(1))
                    primary_file = self.logs_dir / f"primary-{node_num}.log"
                    
                    if primary_file.exists():
                        log_pairs[node_num] = {
                            'worker': file,
                            'primary': primary_file
                        }
                        print(f"Found matching pair for node {node_num}")
            
            return log_pairs
        except Exception as e:
            print(f"Error accessing directory {self.logs_dir}: {e}")
            return {}

    def analyze_logs(self):
        results = []
        log_pairs = self.find_log_pairs()
        
        if not log_pairs:
            print("No log pairs found!")
            return results

        for node_num, files in log_pairs.items():
            print(f"\nAnalyzing node {node_num}...")
            worker_digests = self.process_worker_file(files['worker'], node_num)
            primary_digests = self.process_primary_file(files['primary'], node_num)
            
            # Print sample of digests found
            if worker_digests:
                sample_digest = next(iter(worker_digests))
                print(f"Sample worker digest: {sample_digest} at {worker_digests[sample_digest]}")
            if primary_digests:
                sample_digest = next(iter(primary_digests))
                print(f"Sample primary digest: {sample_digest} at {primary_digests[sample_digest]}")
            
            for digest in worker_digests.keys():
                if digest in primary_digests:
                    worker_time = worker_digests[digest]
                    primary_time = primary_digests[digest]
                    time_diff = (primary_time - worker_time).total_seconds()
                    results.append({
                        'node': node_num,
                        'digest': digest,
                        'worker_time': worker_time,
                        'primary_time': primary_time,
                        'time_diff': time_diff
                    })

        return results

    def generate_report(self):
        results = self.analyze_logs()
        
        if not results:
            return "No matching log entries found! Please check the console output for debugging information."

        results.sort(key=lambda x: (x['node'], x['time_diff']))
        
        report = []
        report.append("Log Analysis Report")
        report.append("=" * 120)
        report.append(f"Total matches found: {len(results)}")
        report.append("-" * 120)
        report.append(f"{'Node':^6} | {'Digest':^45} | {'Time Diff (ms)':^12} | {'Worker Time':^26} | {'Primary Time':^26}")
        report.append("-" * 120)
        
        for result in results:
            report.append(
                f"{result['node']:^6} | "
                f"{result['digest'][:43]:45} | "
                f"{result['time_diff']*1000:12.3f} | "
                f"{result['worker_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]:26} | "
                f"{result['primary_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]:26}"
            )

        return "\n".join(report)

def main():
    current_dir = Path.cwd()
    logs_dir = current_dir.parent / "logs"
    
    print(f"Script starting, looking for logs in: {logs_dir}")
    
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}")
        return
    
    analyzer = LogAnalyzer(logs_dir)
    report = analyzer.generate_report()
    
    output_file = current_dir / "log_analysis_report.txt"
    with open(output_file, 'w') as f:
        f.write(report)
    
    print("\nReport contents:")
    print(report)

if __name__ == "__main__":
    main()