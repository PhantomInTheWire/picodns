#!/usr/bin/env python3

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def _find_free_port() -> int:
    """Find a free port by binding to port 0 and letting the OS assign one."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BenchmarkRunnerBase:
    def __init__(self):
        self.root_dir = Path(__file__).parent.parent.resolve()
        self.duration = int(os.getenv("DURATION", "10"))
        self.qps = int(os.getenv("QPS", "30000"))
        self.udp_sockets = int(os.getenv("UDP_SOCKETS", "4"))
        self.query_file = Path(os.getenv("QUERY_FILE", self.root_dir / "queries.txt"))
        self.start_delay = int(os.getenv("START_DELAY", "2"))
        self.warmup_duration = int(os.getenv("WARMUP_DURATION", "2"))
        self.warmup_qps = int(os.getenv("WARMUP_QPS", "2000"))

        self._run_id = uuid.uuid4().hex[:8]
        port_env = os.getenv("PORT", "")
        if port_env:
            self.port = int(port_env)
        else:
            self.port = _find_free_port()
        knot_port_env = os.getenv("KNOT_PORT", "")
        if knot_port_env:
            self.knot_port = int(knot_port_env)
        else:
            self.knot_port = _find_free_port()

        self._log_file = Path(f"/tmp/picodns-{self._run_id}.log")
        self._kresd_log_file = Path(f"/tmp/kresd-{self._run_id}.log")
        self.perf_report_path = Path(
            os.getenv(
                "PERF_REPORT_PATH",
                self.root_dir / "perf" / f"picodns-perf-{self._run_id}.json",
            )
        )

        self.picodns_pid: Optional[int] = None
        self.kresd_pid: Optional[int] = None
        self.kresd_dir: Optional[Path] = None
        self.pico_result: Optional[Dict] = None
        self.knot_result: Optional[Dict] = None
        self.pico_stats: Dict[str, Any] = {}

    def _print_header(self, text: str, style: str = "bright_cyan"):
        console.print(f"\n[{style} bold]{text}[/]")
        console.print(f"[{style}]{'=' * len(text)}[/]")

    def _print_subheader(self, text: str, style: str = "cyan"):
        console.print(f"\n[{style}]{text}[/]")
        console.print(f"[{style}]{'-' * len(text)}[/]")

    def _run_dnsperf(
        self, port: int, duration: int, qps: int, warmup: bool = False
    ) -> Tuple[str, Dict]:
        cmd = [
            "dnsperf",
            "-s",
            "127.0.0.1",
            "-p",
            str(port),
            "-d",
            str(self.query_file),
            "-l",
            str(duration),
            "-Q",
            str(qps),
        ]

        if warmup:
            console.print(f"[dim]-- warmup {duration}s @ {qps} QPS[/]")

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr

        if not warmup:
            console.print(output)

        return output, self._parse_dnsperf_output(output)

    def _parse_dnsperf_output(self, output: str) -> Dict:
        result = {
            "queries_sent": 0,
            "queries_completed": 0,
            "queries_lost": 0,
            "qps": 0.0,
            "avg_latency": 0.0,
            "min_latency": 0.0,
            "max_latency": 0.0,
            "noerror": 0,
            "servfail": 0,
            "nxdomain": 0,
        }

        patterns = {
            "queries_sent": r"Queries sent:\s+(\d+)",
            "queries_completed": r"Queries completed:\s+(\d+)",
            "queries_lost": r"Queries lost:\s+(\d+)",
            "qps": r"Queries per second:\s+([\d.]+)",
            "avg_latency": r"Average Latency \(s\):\s+([\d.]+)",
            "min_latency": r"min\s+([\d.]+)",
            "max_latency": r"max\s+([\d.]+)",
            "noerror": r"NOERROR\s+(\d+)",
            "servfail": r"SERVFAIL\s+(\d+)",
            "nxdomain": r"NXDOMAIN\s+(\d+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                if key in [
                    "queries_sent",
                    "queries_completed",
                    "queries_lost",
                    "noerror",
                    "servfail",
                    "nxdomain",
                ]:
                    result[key] = int(match.group(1))
                else:
                    result[key] = float(match.group(1))

        return result

    def _parse_json_logs(self, log_file: Path) -> Dict[str, Any]:
        stats = {}
        if not log_file.exists():
            return stats

        for line in log_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                msg = data.get("msg", "")
                if msg == "server shutdown complete":
                    stats["server"] = data
                elif msg == "resolver cache stats":
                    stats["resolver_cache"] = data
                elif msg == "recursive internal cache stats":
                    stats["recursive_cache"] = data
                elif msg == "transport addr cache stats":
                    stats["addr_cache"] = data
            except json.JSONDecodeError:
                continue

        return stats

    def _create_table(self, title: Optional[str], headers: List[str]) -> Table:
        table = Table(
            title=title, box=box.ROUNDED, show_header=True, header_style="bold"
        )
        for header in headers:
            table.add_column(header)
        return table

    def _format_cache_stats(self, stats: Dict[str, Any]):
        panels = []

        if "server" in stats:
            server = stats["server"]
            table = self._create_table("Server Statistics", ["Metric", "Value"])
            table.add_row("Uptime", f"{server.get('uptime', 0) / 1e9:.2f}s")
            table.add_row("Total Queries", f"{server.get('total_queries', 0):,}")
            table.add_row("Average QPS", f"{server.get('avg_qps', 0):.2f}")
            table.add_row("Dropped Packets", f"{server.get('dropped_packets', 0):,}")
            table.add_row("Handler Errors", f"{server.get('handler_errors', 0):,}")
            table.add_row("Write Errors", f"{server.get('write_errors', 0):,}")
            panels.append(Panel(table, border_style="green"))

        if "resolver_cache" in stats:
            cache = stats["resolver_cache"]
            hits = cache.get("cache_hits", 0)
            misses = cache.get("cache_miss", 0)
            hit_rate = cache.get("cache_hit_rate", 0)
            table = self._create_table("Resolver Cache", ["Metric", "Value"])
            table.add_row("Cache Hits", f"{hits:,}")
            table.add_row("Cache Misses", f"{misses:,}")
            table.add_row("Hit Rate", f"{hit_rate * 100:.2f}%")
            panels.append(Panel(table, border_style="blue"))

        if len(panels) == 2:
            self._print_subheader("Server & Resolver Cache Statistics", "bright_green")
            console.print(Columns(panels, equal=True))
        elif panels:
            for panel in panels:
                console.print(panel)

        if "recursive_cache" in stats or "addr_cache" in stats:
            panels = []

            if "recursive_cache" in stats:
                rec = stats["recursive_cache"]
                if "ns_cache" in rec:
                    ns = rec["ns_cache"]
                    table = self._create_table("NS Cache", ["Metric", "Value"])
                    table.add_row("Gets", f"{ns.get('Gets', 0):,}")
                    table.add_row("Hits", f"{ns.get('Hits', 0):,}")
                    table.add_row("Misses", f"{ns.get('Misses', 0):,}")
                    table.add_row("Sets", f"{ns.get('Sets', 0):,}")
                    table.add_row("Current Size", f"{ns.get('Len', 0):,}")
                    hit_rate = (
                        ns.get("Hits", 0) / ns.get("Gets", 1) * 100
                        if ns.get("Gets", 0) > 0
                        else 0
                    )
                    table.add_row("Hit Rate", f"{hit_rate:.2f}%")
                    panels.append(Panel(table, border_style="yellow"))

                if "delegation_cache" in rec:
                    delg = rec["delegation_cache"]
                    table = self._create_table("Delegation Cache", ["Metric", "Value"])
                    table.add_row("Gets", f"{delg.get('Gets', 0):,}")
                    table.add_row("Hits", f"{delg.get('Hits', 0):,}")
                    table.add_row("Misses", f"{delg.get('Misses', 0):,}")
                    table.add_row("Sets", f"{delg.get('Sets', 0):,}")
                    table.add_row("Current Size", f"{delg.get('Len', 0):,}")
                    hit_rate = (
                        delg.get("Hits", 0) / delg.get("Gets", 1) * 100
                        if delg.get("Gets", 0) > 0
                        else 0
                    )
                    table.add_row("Hit Rate", f"{hit_rate:.2f}%")
                    panels.append(Panel(table, border_style="magenta"))

            if "addr_cache" in stats:
                addr = stats["addr_cache"]
                table = self._create_table("Address Cache", ["Metric", "Value"])
                table.add_row("Gets", f"{addr.get('gets', 0):,}")
                table.add_row("Hits", f"{addr.get('hits', 0):,}")
                table.add_row("Misses", f"{addr.get('misses', 0):,}")
                table.add_row("Sets", f"{addr.get('sets', 0):,}")
                table.add_row("Deletes", f"{addr.get('deletes', 0):,}")
                table.add_row("Current Size", f"{addr.get('len', 0):,}")
                hit_rate = addr.get("hit_rate", 0)
                table.add_row("Hit Rate", f"{hit_rate * 100:.2f}%")
                panels.append(Panel(table, border_style="cyan"))

            if panels:
                self._print_subheader("Cache Statistics", "bright_yellow")
                console.print(Columns(panels, equal=True))

    def _format_perf_report(self, report_path: Path) -> None:
        if not report_path.exists():
            return

        try:
            with open(report_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return

        self._print_subheader("Function Performance Profile", "bright_cyan")

        total_runtime_ns = data.get("total_runtime_ns", 0)
        total_calls = data.get("total_calls", 0)

        console.print(f"  Total Runtime: {self._format_duration(total_runtime_ns)}")
        console.print(f"  Total Calls: {total_calls:,}")
        console.print(f"  Sampled Calls: {data.get('sampled_calls', 0):,}")
        console.print()

        functions = data.get("functions", [])
        if not functions:
            return

        # Sort by depth ascending, then by total time descending
        functions = sorted(
            functions, key=lambda f: (f.get("depth", 0), -f.get("total_ns", 0))
        )

        table = Table(
            box=box.ROUNDED, show_header=True, header_style="bold", expand=True
        )
        table.add_column("Function", justify="left", no_wrap=True, min_width=35)
        table.add_column("Calls", justify="right", min_width=8)
        table.add_column("Total", justify="right", min_width=8)
        table.add_column("Avg", justify="right", min_width=8)
        table.add_column("Max", justify="right", min_width=8)
        table.add_column("%", justify="right", min_width=6)

        for i, func in enumerate(functions):
            name = func.get("name", "unknown")
            calls = func.get("calls", 0)
            total_ns = func.get("total_ns", 0)
            avg_ns = func.get("avg_ns", 0)
            max_ns = func.get("max_ns", 0)
            depth = func.get("depth", 0)

            pct = (total_ns / total_runtime_ns * 100) if total_runtime_ns > 0 else 0
            total_str = self._format_duration(total_ns)
            avg_str = self._format_duration(avg_ns)
            max_str = self._format_duration(max_ns)

            if pct > 20:
                pct_text = f"[bright_red]{pct:5.1f}%[/]"
            elif pct > 10:
                pct_text = f"[bright_yellow]{pct:5.1f}%[/]"
            elif pct > 5:
                pct_text = f"[bright_green]{pct:5.1f}%[/]"
            else:
                pct_text = f"{pct:5.1f}%"

            prefix = "  " * depth
            if depth > 0:
                prefix += "└── "
            display_name = prefix + name

            table.add_row(
                display_name, f"{calls:,}", total_str, avg_str, max_str, pct_text
            )

        console.print(table)

        self._format_breakdowns(data)
        console.print(f"\n[dim]Report saved to: {report_path}[/]")

    def _format_breakdowns(self, data: Dict[str, Any]) -> None:
        funcs = data.get("functions", []) or []
        by_name = {f.get("name"): f for f in funcs if f.get("name")}

        def total_ns(name: str) -> int:
            return int(by_name.get(name, {}).get("total_ns", 0) or 0)

        def calls(name: str) -> int:
            return int(by_name.get(name, {}).get("calls", 0) or 0)

        def breakdown(title: str, root: str, components: List[str]) -> None:
            root_total = total_ns(root)
            if root_total <= 0:
                return

            comp_totals = [(name, total_ns(name)) for name in components]
            known = sum(ns for _, ns in comp_totals)
            other = max(0, root_total - known)

            self._print_subheader(title, "bright_cyan")
            t = Table(
                box=box.ROUNDED, show_header=True, header_style="bold", expand=True
            )
            t.add_column("Component", justify="left", no_wrap=True)
            t.add_column("Calls", justify="right")
            t.add_column("Total", justify="right")
            t.add_column(f"% {root}", justify="right")

            for name, ns in comp_totals:
                pct = (ns / root_total * 100) if root_total > 0 else 0
                t.add_row(
                    name, f"{calls(name):,}", self._format_duration(ns), f"{pct:5.1f}%"
                )

            pct_other = (other / root_total * 100) if root_total > 0 else 0
            t.add_row(
                f"{root}.other", "-", self._format_duration(other), f"{pct_other:5.1f}%"
            )
            console.print(t)

        breakdown(
            "Network Breakdown (Sampled)",
            "queryUDP",
            ["queryUDP.netRead", "queryUDP.netWrite", "queryUDP.netDeadline"],
        )
        breakdown(
            "Recursive.resolveIterative Breakdown (Sampled)",
            "Recursive.resolveIterative",
            [
                "Recursive.resolveIterative.hopWait",
                "Recursive.resolveIterative.parseMsg",
                "Recursive.resolveIterative.referral",
                "Recursive.resolveIterative.resolveNS",
                "Recursive.resolveIterative.minimize",
            ],
        )
        breakdown(
            "Cached.Resolve Breakdown (Sampled)",
            "Cached.Resolve",
            [
                "Cached.Resolve.fastPath",
                "Cached.Resolve.parseReq",
                "Cached.Resolve.inflightWait",
                "Cached.Resolve.upstream",
                "Cached.Resolve.validate",
                "Cached.Resolve.cacheSet",
            ],
        )

    def _format_duration(self, ns: int) -> str:
        if ns < 1000:
            return f"{ns}ns"
        elif ns < 1_000_000:
            return f"{ns / 1000:.1f}µs"
        elif ns < 1_000_000_000:
            return f"{ns / 1_000_000:.1f}ms"
        else:
            return f"{ns / 1_000_000_000:.2f}s"

    def _create_results_table(self, title: str, result: Dict, style: str) -> Panel:
        """Create a results table wrapped in a panel."""
        table = self._create_table(None, ["Metric", "Value"])
        table.add_row("Queries Sent", f"{result.get('queries_sent', 0):,}")
        table.add_row("Queries Completed", f"{result.get('queries_completed', 0):,}")
        table.add_row("Queries Lost", f"{result.get('queries_lost', 0):,}")
        table.add_row("Queries/Second", f"{result.get('qps', 0):.2f}")
        table.add_row("Avg Latency", f"{result.get('avg_latency', 0) * 1000:.3f}ms")
        table.add_row("Min Latency", f"{result.get('min_latency', 0) * 1000:.3f}ms")
        table.add_row("Max Latency", f"{result.get('max_latency', 0) * 1000:.3f}ms")
        table.add_row("─" * 15, "─" * 10)
        noerror = result.get("noerror", 0)
        servfail = result.get("servfail", 0)
        nxdomain = result.get("nxdomain", 0)
        total = noerror + servfail + nxdomain
        if total > 0:
            table.add_row("NOERROR", f"{noerror:,} ({noerror / total * 100:.1f}%)")
            table.add_row("SERVFAIL", f"{servfail:,} ({servfail / total * 100:.1f}%)")
            table.add_row("NXDOMAIN", f"{nxdomain:,} ({nxdomain / total * 100:.1f}%)")
        else:
            table.add_row("NOERROR", f"{noerror:,}")
            table.add_row("SERVFAIL", f"{servfail:,}")
            table.add_row("NXDOMAIN", f"{nxdomain:,}")
        return Panel(table, title=title, border_style=style)

    def _print_summary(self):
        self._print_header("BENCHMARK SUMMARY", "bright_cyan")

        if self.pico_result and self.knot_result:
            self._print_subheader("Benchmark Results", "bright_green")
            pico_panel = self._create_results_table(
                "[bold bright_green]PicoDNS[/]", self.pico_result, "green"
            )
            knot_panel = self._create_results_table(
                "[bold bright_yellow]Knot Resolver[/]", self.knot_result, "yellow"
            )
            console.print(Columns([pico_panel, knot_panel], equal=True))
        elif self.pico_result:
            self._print_subheader("PicoDNS Results", "bright_green")
            console.print(
                self._create_results_table("PicoDNS", self.pico_result, "green")
            )

        if self.pico_stats:
            self._format_cache_stats(self.pico_stats)

        self._format_perf_report(self.perf_report_path)

        if self.pico_result and self.knot_result:
            self._print_subheader("Performance Comparison", "bright_magenta")
            p_qps = self.pico_result.get("qps", 0)
            k_qps = self.knot_result.get("qps", 0)

            if k_qps > 0 and p_qps > 0:
                ratio = p_qps / k_qps
                if ratio > 1:
                    console.print(
                        f"  PicoDNS is [bright_green]{ratio:.2f}x faster[/] than Knot Resolver"
                    )
                else:
                    console.print(
                        f"  PicoDNS is [bright_red]{1 / ratio:.2f}x slower[/] than Knot Resolver"
                    )

            p_lat = self.pico_result.get("avg_latency", 0) * 1000
            k_lat = self.knot_result.get("avg_latency", 0) * 1000
            if k_lat > 0:
                lat_diff = ((k_lat - p_lat) / k_lat) * 100
                if lat_diff > 0:
                    console.print(
                        f"  PicoDNS has [bright_green]{lat_diff:.1f}% lower latency[/]"
                    )
                else:
                    console.print(
                        f"  PicoDNS has [bright_red]{abs(lat_diff):.1f}% higher latency[/]"
                    )

    def _cleanup(self):
        if self.picodns_pid:
            try:
                os.kill(self.picodns_pid, signal.SIGTERM)
                os.waitpid(self.picodns_pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

        if self.kresd_pid:
            try:
                os.kill(self.kresd_pid, signal.SIGTERM)
                os.waitpid(self.kresd_pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

        if self.kresd_dir and self.kresd_dir.exists():
            shutil.rmtree(self.kresd_dir, ignore_errors=True)

    def _check_dependencies(self) -> bool:
        if not shutil.which("dnsperf"):
            console.print(
                "[bright_red]Error:[/] dnsperf not found. Install with: brew install dnsperf",
                style="red",
            )
            return False
        return True

    def _build_picodns(self) -> bool:
        console.print("[dim]Building PicoDNS with performance tags...[/]")
        result = subprocess.run(
            ["make", "build-perf"], cwd=self.root_dir, capture_output=True
        )
        if result.returncode != 0:
            console.print("[bright_red]Build failed:[/]", style="red")
            console.print(result.stderr.decode())
            return False
        return True

    def _start_picodns(self) -> bool:
        if self.perf_report_path.exists():
            self.perf_report_path.unlink()

        if self._log_file.exists():
            self._log_file.write_text("")

        cmd = [
            str(self.root_dir / "bin" / "picodns"),
            "-recursive",
            "-listen",
            f"127.0.0.1:{self.port}",
            "-stats",
            "-perf-report",
            str(self.perf_report_path),
        ]

        log_level = os.getenv("PICODNS_LOG_LEVEL", "").strip()
        if log_level:
            cmd.extend(["-log-level", log_level])

        with open(self._log_file, "w") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
            self.picodns_pid = proc.pid

        time.sleep(self.start_delay)

        try:
            os.kill(self.picodns_pid, 0)
        except ProcessLookupError:
            console.print(
                f"[bright_red]Error:[/] PicoDNS failed to start. Check {self._log_file}",
                style="red",
            )
            return False

        return True

    def _start_knot(self) -> bool:
        if not shutil.which("kresd"):
            console.print("[dim]kresd not found; skipping Knot comparison[/]")
            return False

        self.kresd_dir = Path(tempfile.mkdtemp())
        config_file = self.kresd_dir / "config"
        config_file.write_text(
            f"net.listen('127.0.0.1', {self.knot_port})\ncache.size = 100 * MB\n"
        )

        with open(self._kresd_log_file, "w") as log:
            proc = subprocess.Popen(
                ["kresd", "-n", "-q", "-c", "config", str(self.kresd_dir)],
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=self.kresd_dir,
            )
            self.kresd_pid = proc.pid

        time.sleep(self.start_delay)

        try:
            os.kill(self.kresd_pid, 0)
        except ProcessLookupError:
            console.print(
                f"[yellow]Warning:[/] kresd failed to start. Check {self._kresd_log_file}",
                style="yellow",
            )
            self.kresd_dir = None
            return False

        return True

    def run(self) -> int:
        if not self._check_dependencies():
            return 1

        if not self._build_picodns():
            return 1

        try:
            console.print(f"\n[bright_cyan bold]== PicoDNS recursive (local) ==[/]")
            if not self._start_picodns():
                return 1

            if self.warmup_duration > 0:
                self._run_dnsperf(
                    self.port,
                    self.warmup_duration,
                    self.warmup_qps,
                    warmup=True,
                )

            _, self.pico_result = self._run_dnsperf(self.port, self.duration, self.qps)

            self._cleanup()
            self.pico_stats = self._parse_json_logs(self._log_file)

            console.print(f"\n[bright_yellow bold]== Knot Resolver (local) ==[/]")
            if self._start_knot():
                if self.warmup_duration > 0:
                    self._run_dnsperf(
                        self.knot_port,
                        self.warmup_duration,
                        self.warmup_qps,
                        warmup=True,
                    )

                _, self.knot_result = self._run_dnsperf(
                    self.knot_port, self.duration, self.qps
                )
                self._cleanup()

            self._print_summary()

        finally:
            self._cleanup()

        return 0
