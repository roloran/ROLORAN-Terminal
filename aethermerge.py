#!/usr/bin/env python3
"""Merge two or more CSV files with a pluggable deduplication step."""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence


DEDUPLICATION_COLUMNS = ("Counter", "Origin", "Sender", "SeqNr", "Frequency")
PRECISION_MERGE_COLUMNS = ("Origin", "Sender", "Relay1", "Relay2", "Relay3")
CHRONOLOGICAL_COLUMNS = ("Date", "Time")
REQUIRED_COLUMNS = tuple(
    dict.fromkeys(DEDUPLICATION_COLUMNS + PRECISION_MERGE_COLUMNS + CHRONOLOGICAL_COLUMNS)
)
ROLE_PREFIXES = ("EP ", "FR ", "DA ")


class CsvMergeError(Exception):
    """Base class for user-facing merge errors."""


class InputFileError(CsvMergeError):
    """Raised when an input file cannot be read."""


class HeaderMismatchError(CsvMergeError):
    """Raised when input CSV files do not use the same header."""


class MissingColumnError(CsvMergeError):
    """Raised when an input CSV file misses columns required by the merger."""


class OutputFileError(CsvMergeError):
    """Raised when the output CSV file cannot be written."""


@dataclass(frozen=True)
class CsvRow:
    """A parsed CSV row plus enough source context for later rules."""

    source_file: Path
    source_index: int
    line_number: int
    values: dict[str, str]


@dataclass
class FileMergeStats:
    path: Path
    rows_read: int = 0
    rows_added: int = 0
    duplicates_skipped: int = 0
    rows_refined: int = 0


@dataclass
class MergeStats:
    files_read: int = 0
    rows_read: int = 0
    rows_written: int = 0
    duplicates_skipped: int = 0
    rows_refined: int = 0
    files: list[FileMergeStats] = field(default_factory=list)


class RdcpPacketDeduplicator:
    """Deduplicate rows that describe the same sniffed RDCP packet."""

    def __init__(self) -> None:
        self.kept_rows_by_key: dict[tuple[str, ...], CsvRow] = {}

    def dedupe_key(self, row: CsvRow) -> tuple[str, ...]:
        return tuple(
            normalize_dedupe_cell(column, row.values.get(column, ""))
            for column in DEDUPLICATION_COLUMNS
        )

    def mark_seen(self, row: CsvRow) -> None:
        self.kept_rows_by_key.setdefault(self.dedupe_key(row), row)

    def find_duplicate(self, row: CsvRow) -> CsvRow | None:
        key = self.dedupe_key(row)
        return self.kept_rows_by_key.get(key)


def normalize_cell(value: str | None) -> str:
    return "" if value is None else value.strip()


def strip_role_prefix(value: str) -> str:
    for prefix in ROLE_PREFIXES:
        if value.startswith(prefix):
            return value.removeprefix(prefix).strip()

    return value


def normalize_dedupe_cell(column: str, value: str | None) -> str:
    normalized = normalize_cell(value)
    if column in {"Origin", "Sender"}:
        return strip_role_prefix(normalized)

    return normalized


def has_role_prefix(value: str | None) -> bool:
    normalized = normalize_cell(value)
    return any(normalized.startswith(prefix) for prefix in ROLE_PREFIXES)


def origin_sender_precision_score(row: CsvRow) -> int:
    return sum(1 for column in ("Origin", "Sender") if has_role_prefix(row.values.get(column)))


def merge_precise_role_information(target_row: CsvRow, source_row: CsvRow) -> bool:
    source_precision = origin_sender_precision_score(source_row)
    target_precision = origin_sender_precision_score(target_row)

    if source_precision <= target_precision:
        return False

    changed = False
    for column in PRECISION_MERGE_COLUMNS:
        source_value = source_row.values.get(column)
        if source_value is not None and target_row.values.get(column) != source_value:
            target_row.values[column] = source_value
            changed = True

    return changed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aethermerge",
        description="Merge two or more CSV files and write a deduplicated CSV.",
    )
    parser.add_argument(
        "inputs",
        metavar="INPUT",
        nargs="*",
        type=Path,
        help="input CSV file; pass at least two",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        type=Path,
        help="new CSV file to write",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace OUTPUT if it already exists",
    )
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> bool:
    errors: list[str] = []

    if args.output is None:
        errors.append("missing required -o/--output argument")

    if len(args.inputs) < 2:
        errors.append("at least two input CSV files are required")

    if not errors:
        return True

    parser.print_help(sys.stderr)
    print(file=sys.stderr)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)

    return False


def read_csv_file(path: Path, source_index: int) -> tuple[list[str], list[CsvRow]]:
    if not path.exists():
        raise InputFileError(f"input file does not exist: {path}")

    if not path.is_file():
        raise InputFileError(f"input path is not a file: {path}")

    try:
        with path.open("r", newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                raise InputFileError(f"input file is empty or has no header row: {path}")

            columns = list(reader.fieldnames)
            rows = [
                CsvRow(
                    source_file=path,
                    source_index=source_index,
                    line_number=line_number,
                    values=dict(row),
                )
                for line_number, row in enumerate(reader, start=2)
            ]
    except UnicodeDecodeError as exc:
        raise InputFileError(f"input file is not valid UTF-8 text: {path}") from exc
    except csv.Error as exc:
        raise InputFileError(f"input file is not valid CSV: {path}: {exc}") from exc
    except OSError as exc:
        raise InputFileError(f"cannot read input file: {path}: {exc}") from exc

    return columns, rows


def ensure_required_columns(columns: Sequence[str]) -> None:
    missing_columns = [column for column in REQUIRED_COLUMNS if column not in columns]
    if missing_columns:
        raise MissingColumnError(
            "input CSV header is missing required column(s): " + ", ".join(missing_columns)
        )


def read_inputs(paths: Iterable[Path]) -> tuple[list[str], list[CsvRow], MergeStats]:
    expected_columns: list[str] | None = None
    all_rows: list[CsvRow] = []
    stats = MergeStats()

    for source_index, path in enumerate(paths):
        columns, rows = read_csv_file(path, source_index)

        if expected_columns is None:
            expected_columns = columns
            ensure_required_columns(expected_columns)
        elif columns != expected_columns:
            raise HeaderMismatchError(
                "input CSV headers differ: "
                f"{path} has {columns}, expected {expected_columns}"
            )

        stats.files_read += 1
        stats.rows_read += len(rows)
        stats.files.append(FileMergeStats(path=path, rows_read=len(rows)))
        all_rows.extend(rows)

    if expected_columns is None:
        raise InputFileError("no input CSV files were provided")

    return expected_columns, all_rows, stats


def deduplicate_rows(
    rows: Iterable[CsvRow],
    file_stats: Sequence[FileMergeStats],
) -> tuple[list[CsvRow], int]:
    deduplicator = RdcpPacketDeduplicator()
    kept_rows: list[CsvRow] = []
    skipped = 0

    for row in rows:
        current_file_stats = file_stats[row.source_index]

        if row.source_index == 0:
            kept_rows.append(row)
            current_file_stats.rows_added += 1
            deduplicator.mark_seen(row)
            continue

        duplicate_row = deduplicator.find_duplicate(row)
        if duplicate_row is not None:
            skipped += 1
            current_file_stats.duplicates_skipped += 1
            if merge_precise_role_information(duplicate_row, row):
                current_file_stats.rows_refined += 1
            continue

        kept_rows.append(row)
        current_file_stats.rows_added += 1
        deduplicator.mark_seen(row)

    return kept_rows, skipped


def parse_row_datetime(row: CsvRow) -> datetime:
    raw_date = normalize_cell(row.values.get("Date"))
    raw_time = normalize_cell(row.values.get("Time"))

    try:
        return datetime.fromisoformat(f"{raw_date}T{raw_time}")
    except ValueError as exc:
        raise InputFileError(
            f"cannot parse Date/Time in {row.source_file}:{row.line_number}: "
            f"{raw_date!r} {raw_time!r}"
        ) from exc


def sort_rows_chronologically(rows: Iterable[CsvRow]) -> list[CsvRow]:
    return sorted(rows, key=parse_row_datetime)


def write_csv_file(path: Path, columns: Sequence[str], rows: Iterable[CsvRow], overwrite: bool) -> int:
    if path.exists() and not overwrite:
        raise OutputFileError(f"output file already exists: {path} (use --overwrite to replace it)")

    output_dir = path.parent if path.parent != Path("") else Path(".")
    temp_path: Path | None = None

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            newline="",
            encoding="utf-8",
            dir=output_dir,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as csv_file:
            temp_path = Path(csv_file.name)
            writer = csv.DictWriter(
                csv_file,
                fieldnames=list(columns),
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()

            written = 0
            for row in rows:
                writer.writerow(row.values)
                written += 1

        temp_path.replace(path)
    except OSError as exc:
        raise OutputFileError(f"cannot write output file: {path}: {exc}") from exc
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

    return written


def ensure_output_is_not_an_input(input_paths: Sequence[Path], output_path: Path) -> None:
    output_resolved = output_path.resolve(strict=False)

    for input_path in input_paths:
        if input_path.resolve(strict=False) == output_resolved:
            raise OutputFileError(f"output file must not be the same as an input file: {output_path}")


def merge_csv_files(input_paths: Sequence[Path], output_path: Path, overwrite: bool = False) -> MergeStats:
    ensure_output_is_not_an_input(input_paths, output_path)
    columns, rows, stats = read_inputs(input_paths)
    kept_rows, skipped = deduplicate_rows(rows, stats.files)
    kept_rows = sort_rows_chronologically(kept_rows)

    stats.duplicates_skipped = skipped
    stats.rows_refined = sum(file_stats.rows_refined for file_stats in stats.files)
    stats.rows_written = write_csv_file(output_path, columns, kept_rows, overwrite)

    return stats


def format_stats_table(stats: MergeStats) -> str:
    headers = ("File", "Lines", "Added", "Duplicates", "Refined")
    rows = [
        (
            str(file_stats.path),
            str(file_stats.rows_read),
            str(file_stats.rows_added),
            str(file_stats.duplicates_skipped),
            str(file_stats.rows_refined),
        )
        for file_stats in stats.files
    ]

    widths = [
        max(len(headers[column_index]), *(len(row[column_index]) for row in rows))
        for column_index in range(len(headers))
    ]

    def format_row(row: Sequence[str]) -> str:
        return (
            f"{row[0]:<{widths[0]}}  "
            f"{row[1]:>{widths[1]}}  "
            f"{row[2]:>{widths[2]}}  "
            f"{row[3]:>{widths[3]}}  "
            f"{row[4]:>{widths[4]}}"
        )

    table_lines = [
        format_row(headers),
        format_row(
            (
                "-" * widths[0],
                "-" * widths[1],
                "-" * widths[2],
                "-" * widths[3],
                "-" * widths[4],
            )
        ),
    ]
    table_lines.extend(format_row(row) for row in rows)

    return "\n".join(table_lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not validate_args(args, parser):
        return 2

    try:
        stats = merge_csv_files(args.inputs, args.output, args.overwrite)
    except CsvMergeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        "merged "
        f"{stats.files_read} files, "
        f"read {stats.rows_read} rows, "
        f"wrote {stats.rows_written} rows, "
        f"skipped {stats.duplicates_skipped} duplicates, "
        f"refined {stats.rows_refined} rows"
    )
    print()
    print(format_stats_table(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
