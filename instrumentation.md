# Source Instrumentation Notes

The checked-in IPv4/IPv6 binaries are PyInstaller bundles. That makes the
Windows path slow and mostly opaque, but the extracted Linux payloads contain
importable `buggy_ipyparse` modules that can be exercised directly from WSL.

## Use the lightweight runner

From WSL in the repo root:

```bash
python3 tools/ip_parser_source_runner.py ipv4 --ipstr 1.2.3.4
printf '2001:db8::1' | python3 tools/ip_parser_source_runner.py ipv6 --stdin
```

This bypasses the `pandas`-heavy top-level PyInstaller launcher and executes the
parser logic directly from `linux-ipv4-parser_extracted/PYZ.pyz_extracted` or
`linux-ipv6-parser_extracted/PYZ.pyz_extracted`.

## coverage.py example

If `coverage.py` is installed in WSL:

```bash
coverage run --branch tools/ip_parser_source_runner.py ipv4 --ipstr 1.2.3.4
coverage report
coverage html
```

## python-afl example

If `python-afl` is installed in WSL:

```bash
py-afl-fuzz -i corpus -o findings -- \
  python3 tools/ip_parser_source_runner.py ipv4 --stdin --persistent 1000
```

`--stdin` keeps the harness fuzz-friendly, and `--persistent` lets
`python-afl` process many test cases per fork for better throughput.

For a lower-overhead hot path, use the dedicated AFL harness:

```bash
mkdir -p afl-ipv4-in afl-ipv4-out
printf '1.2.3.4' > afl-ipv4-in/seed.txt

py-afl-fuzz -i afl-ipv4-in -o afl-ipv4-out -- \
  python3 tools/ip_parser_afl_harness.py ipv4 --persistent 1000 --fast-exit
```

This harness preloads the parser once, reads each test case from stdin, and
swallows only expected invalid-input exceptions so unexpected failures still
surface as AFL crashes.
