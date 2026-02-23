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
        self.qps = int(os.getenv("QPS", "50000"))
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

        version = int(data.get("version", 1) or 1)
        wall_time_ns = int(
            data.get("wall_time_ns", data.get("total_runtime_ns", 0) or 0) or 0
        )
        total_calls = int(data.get("total_calls", 0) or 0)
        sampled_calls = int(data.get("sampled_calls", 0) or 0)

        sample_rate = int(data.get("sample_rate", 0) or 0)
        warmup_samples = int(data.get("warmup_samples", 0) or 0)

        label = "Wall Time" if version >= 2 else "Total Runtime"
        console.print(f"  {label}: {self._format_duration(wall_time_ns)}")
        console.print(f"  Total Calls: {total_calls:,}")
        console.print(f"  Sampled Calls: {sampled_calls:,}")
        if version >= 2 and sample_rate:
            console.print(
                f"  Sample Rate: 1/{sample_rate} | Warmup Samples/Func: {warmup_samples}"
            )
        if version >= 2:
            console.print(
                "  Note: times are aggregate (sum across calls); they are not CPU time and can exceed wall time under concurrency/IO waits"
            )
        console.print()

        functions = data.get("functions", [])
        if not functions:
            return

        by_name = {f.get("name"): f for f in functions if f.get("name")}

        def _ns(func: Dict[str, Any], key: str, fallback: int = 0) -> int:
            try:
                return int(func.get(key, fallback) or 0)
            except Exception:
                return fallback

        def _sampled_total_ns(func: Dict[str, Any]) -> int:
            return _ns(func, "sampled_total_ns", _ns(func, "total_ns", 0))

        # Build a stable call tree using explicit parent links (v2).
        children: Dict[str, List[Dict[str, Any]]] = {}
        roots: List[Dict[str, Any]] = []
        if version >= 2:
            for f in functions:
                name = (f.get("name") or "").strip()
                if not name:
                    continue
                parent = (f.get("parent") or "").strip()
                if parent:
                    children.setdefault(parent, []).append(f)
                else:
                    roots.append(f)
            for k in list(children.keys()):
                children[k].sort(key=lambda x: -_sampled_total_ns(x))
            roots.sort(key=lambda x: -_sampled_total_ns(x))
        else:
            # v1 has only a depth heuristic.
            functions = sorted(
                functions,
                key=lambda f: (int(f.get("depth", 0) or 0), -_ns(f, "total_ns", 0)),
            )

        table = Table(
            box=box.ROUNDED, show_header=True, header_style="bold", expand=True
        )
        table.add_column("Function", justify="left", no_wrap=True, min_width=35)
        table.add_column("Calls", justify="right", min_width=8)
        table.add_column("Sampled", justify="right", min_width=8)
        table.add_column("Sampled Total", justify="right", min_width=12)
        table.add_column("Avg", justify="right", min_width=8)
        table.add_column("Max", justify="right", min_width=8)
        table.add_column("%Parent", justify="right", min_width=8)

        def _pct_parent(child: Dict[str, Any]) -> str:
            if version < 2:
                return "-"
            parent_name = (child.get("parent") or "").strip()
            if not parent_name:
                return "-"
            parent = by_name.get(parent_name)
            if not parent:
                return "-"
            # Only show %Parent when it's plausibly nested under the same sampling decision.
            try:
                c_s = int(child.get("sampled", 0) or 0)
                p_s = int(parent.get("sampled", 0) or 0)
                if c_s <= 0 or p_s <= 0 or c_s > p_s:
                    return "-"
            except Exception:
                return "-"
            p_total = _sampled_total_ns(parent)
            c_total = _sampled_total_ns(child)
            if p_total <= 0 or c_total <= 0:
                return "-"
            pct = (c_total / p_total) * 100.0
            if pct > 1000:
                return ">1000%"
            if pct > 20:
                return f"[bright_red]{pct:6.1f}%[/]"
            if pct > 10:
                return f"[bright_yellow]{pct:6.1f}%[/]"
            if pct > 5:
                return f"[bright_green]{pct:6.1f}%[/]"
            return f"{pct:6.1f}%"

        def _add_row(func: Dict[str, Any], depth: int) -> None:
            name = (func.get("name") or "unknown").strip() or "unknown"
            calls = int(func.get("calls", 0) or 0)
            sampled = int(func.get("sampled", 0) or 0)
            sampled_total_ns = _sampled_total_ns(func)
            avg_ns = _ns(func, "avg_ns", 0)
            max_ns = _ns(func, "max_ns", 0)

            prefix = "  " * depth
            if depth > 0:
                prefix += "└── "
            display_name = prefix + name

            table.add_row(
                display_name,
                f"{calls:,}",
                f"{sampled:,}",
                self._format_duration(sampled_total_ns),
                self._format_duration(avg_ns),
                self._format_duration(max_ns),
                _pct_parent(func),
            )

        if version >= 2 and roots:

            def walk(node: Dict[str, Any], depth: int, seen: set) -> None:
                name = (node.get("name") or "").strip()
                if not name or name in seen:
                    return
                seen.add(name)
                _add_row(node, depth)
                for ch in children.get(name, []):
                    walk(ch, depth + 1, seen)

            seen_names: set = set()
            for root in roots:
                walk(root, 0, seen_names)
        else:
            for func in functions:
                depth = int(func.get("depth", 0) or 0)
                _add_row(func, depth)

        console.print(table)

        self._format_breakdowns(data)
        console.print(f"\n[dim]Report saved to: {report_path}[/]")

    def _format_breakdowns(self, data: Dict[str, Any]) -> None:
        funcs = data.get("functions", []) or []
        by_name = {f.get("name"): f for f in funcs if f.get("name")}

        def total_ns(name: str) -> int:
            f = by_name.get(name, {})
            return int(f.get("sampled_total_ns", f.get("total_ns", 0) or 0) or 0)

        def sampled_calls(name: str) -> int:
            return int(by_name.get(name, {}).get("sampled", 0) or 0)

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
            t.add_column("Sampled", justify="right")
            t.add_column("Total", justify="right")
            t.add_column(f"% {root}", justify="right")

            for name, ns in comp_totals:
                pct = (ns / root_total * 100) if root_total > 0 else 0
                t.add_row(
                    name,
                    f"{sampled_calls(name):,}",
                    self._format_duration(ns),
                    f"{pct:5.1f}%",
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

            p_avg = self.pico_result.get("avg_latency", 0) * 1000
            k_avg = self.knot_result.get("avg_latency", 0) * 1000
            if k_avg > 0:
                avg_diff = ((k_avg - p_avg) / k_avg) * 100
                if avg_diff > 0:
                    console.print(
                        f"  Avg latency:  [bright_green]{avg_diff:.1f}% lower[/] ({p_avg:.3f}ms vs {k_avg:.3f}ms)"
                    )
                else:
                    console.print(
                        f"  Avg latency:  [bright_red]{abs(avg_diff):.1f}% higher[/] ({p_avg:.3f}ms vs {k_avg:.3f}ms)"
                    )

            p_max = self.pico_result.get("max_latency", 0) * 1000
            k_max = self.knot_result.get("max_latency", 0) * 1000
            if k_max > 0:
                max_diff = ((k_max - p_max) / k_max) * 100
                if max_diff > 0:
                    console.print(
                        f"  Max latency:  [bright_green]{max_diff:.1f}% lower[/] ({p_max:.3f}ms vs {k_max:.3f}ms)"
                    )
                else:
                    console.print(
                        f"  Max latency:  [bright_red]{abs(max_diff):.1f}% higher[/] ({p_max:.3f}ms vs {k_max:.3f}ms)"
                    )

            p_lost = self.pico_result.get("queries_lost", 0)
            k_lost = self.knot_result.get("queries_lost", 0)
            if p_lost == 0 and k_lost > 0:
                console.print(f"  Queries lost: [bright_green]0 vs {k_lost}[/]")
            elif p_lost > 0 and k_lost == 0:
                console.print(f"  Queries lost: [bright_red]{p_lost} vs 0[/]")
            elif p_lost > 0 or k_lost > 0:
                console.print(f"  Queries lost: {p_lost} vs {k_lost}")

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
            "-prewarm=false",
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
