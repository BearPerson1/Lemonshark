import sys
import os

# usage: python run_log_parsing.py ../benchmark/logs 0
# 0 is num faults

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark.logs import LogParser, ParseError
from benchmark.utils import PathMaker

def main(logs_path, faults):
    try:
        print(f"Parsing logs from: {logs_path}")
        parser = LogParser.process(logs_path, faults=faults)
        print(parser.result())
    except ParseError as e:
        print(f'Failed to parse logs: {e}')
        sys.exit(1)
    except AssertionError as e:
        print(f'Assertion Error: {e}')
        print("One of the inputs (clients, primaries, or workers) is empty. Please check the logs directory.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python run_log_parsing.py <relative_logs_path> <faults>")
        sys.exit(1)

    # Get the absolute path to the logs directory
    logs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', sys.argv[1]))
    faults = int(sys.argv[2])

    main(logs_path, faults)