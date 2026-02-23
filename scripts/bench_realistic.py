#!/usr/bin/env python3

import csv
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bench_base import BenchmarkRunnerBase, console


class RealisticBenchmarkRunner(BenchmarkRunnerBase):
    MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"

    def __init__(self):
        super().__init__()
        self.majestic_count = int(os.getenv("MAJESTIC_COUNT", "10000"))
        self.total_queries = int(os.getenv("REALISTIC_TOTAL", "10000"))
        self.common_pct = int(os.getenv("REALISTIC_COMMON_PCT", "70"))
        self.cache_dir = Path(os.getenv("MAJESTIC_CACHE_DIR", "/tmp/majestic"))
        self.cache_file = self.cache_dir / "majestic_million.csv"
        self.common_query_file = self.root_dir / "queries.txt"
        self.query_file = Path("/tmp/queries_realistic.txt")

    def _download_majestic_csv(self) -> bool:
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if self.cache_file.exists():
            console.print(
                f"[dim]Using cached Majestic Million CSV: {self.cache_file}[/]"
            )
            return True

        console.print("[dim]Downloading Majestic Million CSV...[/]")
        try:
            from urllib.request import urlretrieve

            urlretrieve(self.MAJESTIC_URL, self.cache_file)
            console.print(f"[green]Downloaded to: {self.cache_file}[/]")
            return True
        except Exception as e:
            console.print(f"[red]Failed to download Majestic Million CSV: {e}[/]")
            return False

    def _load_common_domains(self) -> list:
        if not self.common_query_file.exists():
            console.print(
                f"[red]Common query file not found: {self.common_query_file}[/]"
            )
            return []

        domains = []
        for line in self.common_query_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
        return domains

    def _load_majestic_domains(self) -> list:
        if not self.cache_file.exists():
            console.print(f"[red]Cache file not found: {self.cache_file}[/]")
            return []

        domains = []
        with open(self.cache_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header

            for i, row in enumerate(reader):
                if i >= self.majestic_count:
                    break
                if len(row) >= 3:
                    domain = row[2].strip()
                    if domain:
                        domains.append(f"{domain} A")
        return domains

    def _generate_query_file(self) -> bool:
        common_domains = self._load_common_domains()
        if not common_domains:
            console.print("[red]No common domains loaded[/]")
            return False

        majestic_domains = self._load_majestic_domains()
        if not majestic_domains:
            console.print("[red]No majestic domains loaded[/]")
            return False

        common_count = int(self.total_queries * self.common_pct / 100)
        majestic_count = self.total_queries - common_count

        queries = []
        queries.extend(random.choices(common_domains, k=common_count))
        queries.extend(random.choices(majestic_domains, k=majestic_count))
        random.shuffle(queries)

        self.query_file.write_text("\n".join(queries) + "\n")

        actual_common_pct = common_count / self.total_queries * 100
        actual_majestic_pct = majestic_count / self.total_queries * 100
        console.print(
            f"[green]Generated {self.total_queries} queries: "
            f"{common_count} common ({actual_common_pct:.1f}%), "
            f"{majestic_count} majestic ({actual_majestic_pct:.1f}%)[/]"
        )
        console.print(
            f"[dim]Common pool: {len(common_domains)} domains, "
            f"Majestic pool: {len(majestic_domains)} domains[/]"
        )
        console.print(f"[dim]Query file: {self.query_file}[/]")
        return True

    def run(self) -> int:
        if not self._download_majestic_csv():
            return 1

        if not self._generate_query_file():
            return 1

        console.print(
            f"\n[bright_cyan bold]== Realistic Mixed Benchmark "
            f"({self.common_pct}/{100 - self.common_pct} common/majestic) ==[/]"
        )
        return super().run()


def main():
    runner = RealisticBenchmarkRunner()
    sys.exit(runner.run())


if __name__ == "__main__":
    main()
