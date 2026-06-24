# FFUF Smart Filter

Stream-filter large ffuf TSV exports by response fingerprint.

This tool keeps the first `N` rows for each repeated response shape and
suppresses the rest. It is useful when a ffuf run produces thousands of noisy
matches that share the same status, size, word count, and line count.

By default, the fingerprint is:

```text
host + status + length + words + lines
```

The filter does not decide whether a finding is vulnerable. It keeps a small
sample of each response pattern so you can review the interesting shapes
without drowning in duplicates.

## Usage

Run without arguments to print the help/usage text:

```bash
python3 ffuf_smart_filter.py
```

```bash
python3 ffuf_smart_filter.py results.tsv -o filtered.tsv
```

Keep the first 3 rows for each response fingerprint:

```bash
python3 ffuf_smart_filter.py results.tsv -o filtered.tsv --first 3
```

Read from stdin and write to stdout:

```bash
cat results.tsv | python3 ffuf_smart_filter.py - > filtered.tsv
```

When `-o` is not provided, matching rows are written to stdout:

```bash
python3 ffuf_smart_filter.py results.tsv --quiet > filtered.tsv
```

Treat the first input row as a header and write it back out:

```bash
python3 ffuf_smart_filter.py results.tsv -o filtered.tsv --header --write-header
```

Group fingerprints globally across all hosts:

```bash
python3 ffuf_smart_filter.py results.tsv -o filtered.tsv --global-key
```

Write a report of repeated fingerprints:

```bash
python3 ffuf_smart_filter.py results.tsv \
  -o filtered.tsv \
  --pattern-report patterns.tsv
```

Print rows whose fingerprint appears exactly 5 times:

```bash
python3 ffuf_smart_filter.py results.tsv --show-count 5 -o count-5.tsv
```

Print those rows to stdout instead:

```bash
python3 ffuf_smart_filter.py results.tsv --show-count 5 --quiet
```

## Input Format

For headerless TSV input, the default column order is:

```text
host    status    length    words    lines    url
```

Override headerless columns with `--columns`:

```bash
python3 ffuf_smart_filter.py results.tsv \
  --columns host,status,length,words,lines,url,redirectlocation \
  -o filtered.tsv
```

Use custom fingerprint fields with `--key-fields`:

```bash
python3 ffuf_smart_filter.py results.tsv \
  --key-fields status,length,words,lines \
  -o filtered.tsv
```

## Counting Matches

`--show-count X` prints rows whose fingerprint appears exactly `X` times.

By default, counts are per host because the default fingerprint includes
`host`:

```text
host + status + length + words + lines
```

That means these two rows count together:

```text
a.com    200    1234    50    10    https://a.com/admin
a.com    200    1234    50    10    https://a.com/login
```

But this row is counted separately because the host differs:

```text
b.com    200    1234    50    10    https://b.com/admin
```

Use `--global-key` to count matching response shapes across all hosts:

```bash
python3 ffuf_smart_filter.py results.tsv --show-count 5 --global-key
```

In global mode, the default fingerprint becomes:

```text
status + length + words + lines
```

## Output

Filtered rows are written as TSV. Summary statistics are printed to stderr:

```text
rows=10000 kept=240 suppressed=9760 malformed=0 patterns=24
```

Use `--quiet` to suppress the summary.

When `--show-count` is used, the tool switches from first-N filtering to exact
count matching. It stores valid rows in memory so it can count all fingerprints
before writing the matching rows.
