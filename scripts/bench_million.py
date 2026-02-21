#!/usr/bin/env python3

import csv
import os
import sys
from pathlib import Path
from urllib.request import urlretrieve

sys.path.insert(0, str(Path(__file__).parent))

from bench_base import BenchmarkRunnerBase, console


class MajesticMillionBenchmarkRunner(BenchmarkRunnerBase):
    MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"

    def __init__(self):
        super().__init__()
        self.majestic_count = int(os.getenv("MAJESTIC_COUNT", "10000"))
        self.cache_dir = Path(os.getenv("MAJESTIC_CACHE_DIR", "/tmp/majestic"))
        self.cache_file = self.cache_dir / "majestic_million.csv"
        self.query_file = Path("/tmp/queries.txt")

    def _download_majestic_csv(self) -> bool:
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if self.cache_file.exists():
            console.print(
                f"[dim]Using cached Majestic Million CSV: {self.cache_file}[/]"
            )
            return True

        console.print(f"[dim]Downloading Majestic Million CSV...[/]")
        try:
            urlretrieve(self.MAJESTIC_URL, self.cache_file)
            console.print(f"[green]Downloaded to: {self.cache_file}[/]")
            return True
        except Exception as e:
            console.print(f"[red]Failed to download Majestic Million CSV: {e}[/]")
            return False

    def _generate_query_file(self) -> bool:
        if not self.cache_file.exists():
            console.print(f"[red]Cache file not found: {self.cache_file}[/]")
            return False

        console.print(
            f"[dim]Generating query file with top {self.majestic_count} domains...[/]"
        )

        try:
            domains = []
            with open(self.cache_file, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)

                for i, row in enumerate(reader):
                    if i >= self.majestic_count:
                        break
                    if len(row) >= 3:
                        domain = row[2].strip()
                        if domain:
                            domains.append(f"{domain} A")

            if not domains:
                console.print("[red]No domains found in CSV[/]")
                return False

            query_content = "\n".join(domains)
            self.query_file.write_text(query_content)
            console.print(
                f"[green]Generated query file with {len(domains)} domains: {self.query_file}[/]"
            )
            return True

        except Exception as e:
            console.print(f"[red]Failed to generate query file: {e}[/]")
            return False

    def run(self) -> int:
        if not self._download_majestic_csv():
            return 1

        if not self._generate_query_file():
            return 1

        console.print(
            f"\n[bright_cyan bold]== Majestic Million Benchmark (Top {self.majestic_count} domains) ==[/]"
        )
        return super().run()


def main():
    runner = MajesticMillionBenchmarkRunner()
    sys.exit(runner.run())


if __name__ == "__main__":
    main()
