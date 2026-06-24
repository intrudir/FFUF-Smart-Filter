#!/usr/bin/env python3
"""
Stream-filter large ffuf TSV exports using BypassFuzzer's smart-filter idea.

The filter keeps the first N rows for each response fingerprint and suppresses
the rest. For ffuf TSV exports without response content type, the default
fingerprint is:

    host + status + length + words + lines

This is intentionally simple: it preserves examples from each response shape
without trying to decide what is vulnerable.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence, TextIO


DEFAULT_COLUMNS = ("host", "status", "length", "words", "lines", "url")
DEFAULT_KEY_FIELDS = ("host", "status", "length", "words", "lines")


@dataclass(frozen=True)
class FilterStats:
    total_rows: int
    kept_rows: int
    suppressed_rows: int
    malformed_rows: int
    unique_patterns: int


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smart-filter large ffuf TSV results by response fingerprint."
    )
    parser.add_argument("input", type=Path, help="Input ffuf TSV file, or '-' for stdin")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output TSV file. Defaults to stdout.",
    )
    parser.add_argument(
        "-n",
        "--first",
        type=int,
        default=10,
        help="Keep the first N rows per fingerprint. Default: 10.",
    )
    parser.add_argument(
        "--global-key",
        action="store_true",
        help="Do not include host in the fingerprint. Default is per-host grouping.",
    )
    parser.add_argument(
        "--key-fields",
        default=None,
        help=(
            "Comma-separated fingerprint fields. Default: host,status,length,words,lines "
            "(or status,length,words,lines with --global-key)."
        ),
    )
    parser.add_argument(
        "--columns",
        default=",".join(DEFAULT_COLUMNS),
        help=(
            "Comma-separated column names for headerless TSV input. "
            "Default: host,status,length,words,lines,url."
        ),
    )
    parser.add_argument(
        "--header",
        action="store_true",
        help="Treat the first input row as a header row.",
    )
    parser.add_argument(
        "--write-header",
        action="store_true",
        help="Write a header row to the output.",
    )
    parser.add_argument(
        "--pattern-report",
        type=Path,
        help="Optional TSV report of fingerprint counts, sorted by frequency.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print summary statistics to stderr.",
    )
    if not argv:
        parser.print_help()
        raise SystemExit(0)

    args = parser.parse_args(argv)

    if args.first < 1:
        parser.error("--first must be at least 1")

    return args


def smart_filter(
    input_file: TextIO,
    output_file: TextIO,
    *,
    columns: Sequence[str],
    key_fields: Sequence[str],
    keep_first: int,
    has_header: bool,
    write_header: bool,
) -> tuple[FilterStats, Counter[tuple[str, ...]]]:
    reader = csv.reader(input_file, delimiter="\t")
    writer = csv.writer(output_file, delimiter="\t", lineterminator="\n")

    header = list(columns)
    if has_header:
        try:
            header = next(reader)
        except StopIteration:
            if write_header:
                writer.writerow(header)
            return FilterStats(0, 0, 0, 0, 0), Counter()

    validate_key_fields(header, key_fields)

    if write_header:
        writer.writerow(header)

    key_indexes = [header.index(field) for field in key_fields]
    pattern_counts: Counter[tuple[str, ...]] = Counter()
    total_rows = 0
    kept_rows = 0
    malformed_rows = 0

    for row in reader:
        total_rows += 1
        if len(row) != len(header):
            malformed_rows += 1
            continue

        key = tuple(row[index] for index in key_indexes)
        pattern_counts[key] += 1
        if pattern_counts[key] <= keep_first:
            writer.writerow(row)
            kept_rows += 1

    return (
        FilterStats(
            total_rows=total_rows,
            kept_rows=kept_rows,
            suppressed_rows=total_rows - kept_rows - malformed_rows,
            malformed_rows=malformed_rows,
            unique_patterns=len(pattern_counts),
        ),
        pattern_counts,
    )


def validate_key_fields(columns: Sequence[str], key_fields: Iterable[str]) -> None:
    missing = [field for field in key_fields if field not in columns]
    if missing:
        raise SystemExit(
            "Key field(s) not present in columns: "
            + ", ".join(missing)
            + "\nAvailable columns: "
            + ", ".join(columns)
        )


def write_pattern_report(path: Path, pattern_counts: Counter[tuple[str, ...]], key_fields: Sequence[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as report:
        writer = csv.writer(report, delimiter="\t", lineterminator="\n")
        writer.writerow(("count", *key_fields))
        for key, count in pattern_counts.most_common():
            writer.writerow((count, *key))


def format_summary(stats: FilterStats) -> str:
    return (
        f"rows={stats.total_rows} "
        f"kept={stats.kept_rows} "
        f"suppressed={stats.suppressed_rows} "
        f"malformed={stats.malformed_rows} "
        f"patterns={stats.unique_patterns}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    columns = tuple(field.strip() for field in args.columns.split(",") if field.strip())
    if args.key_fields:
        key_fields = tuple(field.strip() for field in args.key_fields.split(",") if field.strip())
    elif args.global_key:
        key_fields = tuple(field for field in DEFAULT_KEY_FIELDS if field != "host")
    else:
        key_fields = DEFAULT_KEY_FIELDS

    if not columns:
        raise SystemExit("--columns must contain at least one column")
    if not key_fields:
        raise SystemExit("At least one key field is required")

    input_context = (
        nullcontext(sys.stdin)
        if str(args.input) == "-"
        else args.input.open("r", newline="", encoding="utf-8", errors="replace")
    )
    output_context = (
        nullcontext(sys.stdout)
        if args.output is None
        else args.output.open("w", newline="", encoding="utf-8")
    )

    try:
        with input_context as input_file, output_context as output_file:
            stats, pattern_counts = smart_filter(
                input_file,
                output_file,
                columns=columns,
                key_fields=key_fields,
                keep_first=args.first,
                has_header=args.header,
                write_header=args.write_header,
            )
    except BrokenPipeError:
        return 0

    if args.pattern_report:
        write_pattern_report(args.pattern_report, pattern_counts, key_fields)

    if not args.quiet:
        print(format_summary(stats), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
