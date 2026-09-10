# Probe Engine Interface (Rust Primary)

There is ONE scanning engine: Rust.

Python and Go may exist for:
- orchestration
- reporting
- distributed coordination

…but they do NOT implement duplicate scanners.

## Invocation

probe-engine scan --input <target> [--ports 1-1024|80,443] [--timeout-ms 800] [--json]


## Output
- Engine prints JSON ONLY to STDOUT (when --json)
- Output MUST validate against `schemas/scan_result.schema.json`
- Logs go to STDERR only

## Exit Codes
0   Success
1   Invalid input
2   Permission error
3   Network failure
4   Internal engine error

## Signals
- SIGINT: stop cleanly, return partial results if possible
- SIGTERM: stop cleanly
