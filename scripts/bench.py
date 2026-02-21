#!/usr/bin/env python3

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bench_base import BenchmarkRunnerBase


class BenchmarkRunner(BenchmarkRunnerBase):
    pass


def main():
    runner = BenchmarkRunner()
    sys.exit(runner.run())


if __name__ == "__main__":
    main()
