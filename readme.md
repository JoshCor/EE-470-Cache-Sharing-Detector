# Cache Sharing Detector

A CLI tool made with Intel PIN to determine if a multithreaded program has false sharing. Has source lookup capabilies to find the trouble spots in the code so the developer can fix them. Tunable parameters to improve perfomance, and can run studies on programs using python.


## Prerequisites

| Dependency | Notes |
|---|---|
| Intel PIN 4.2 | See download instructions below |
| libdw / elfutils | `sudo pacman -S elfutils` / `sudo apt install libdw-dev` |
| g++ | Any modern version with C++17 support |
| Python 3 | For the CLI and analysis scripts |

## Setup

**1. Download PIN 4.2**

PIN is not redistributable — download it directly from Intel:

https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html

Extract anywhere under `~` — the tool auto-detects it:

```bash
tar -xzf pin-*.tar.gz -C ~/
```

Detection order: `$PIN_ROOT` env var → `~/pin` → any `~/pin-*/` directory (newest wins).
To be explicit, either rename the extracted folder to `~/pin` or set the env var:

```bash
export PIN_ROOT=~/pin-3.31-98869-g71afcc22f-gcc-linux
```

**2. Clone and build**

```bash
git clone <repo-url>
cd cache-sharing-detector
make setup                         # builds tool, source_lookup, creates Python venv
```

If PIN is not at `~/pin-4.2`, pass the path:

```bash
make setup PIN_ROOT=/path/to/pin
```

## Usage

Start the interactive shell from the project root:

```bash
python3 csd.py
```

Everything runs from the `[csd]#` prompt. Type `help` or `help <command>` at any time.

---

### Quick start — single run

Instrument a program once and see the sharing report immediately:

```
[csd]# run xz -T4 -k -f TestingData/testfile.bin
[csd]# lookup
```

`run` streams the detector output to the terminal and saves logs. `lookup` then resolves the hot instruction pointers to source file and line numbers.

To disable call-stack frame capture (faster, no source context):

```
[csd]# run --frames 0 xz -T4 -k -f TestingData/testfile.bin
```

---

### Repeated runs — study

Run a program multiple times to collect statistics across runs:

```
[csd]# study --runs 20 xz -T4 -k -f TestingData/testfile.bin
[csd]# analyze
```

Each run is saved with a timestamp. `analyze` aggregates all CSVs and writes `plots/study.png`. The optional `--name` flag sets the study folder name:

```
[csd]# study --runs 10 --name xz-baseline xz -T4 -k -f TestingData/testfile.bin
```

### Sample-rate sweep

Test how detection accuracy and runtime change across sampling rates (1 = record every access):

```
[csd]# sweep --runs 5 --rates 1,2,4,8,16 xz -T4 -k -f TestingData/testfile.bin
[csd]# analyze
```

To also compare frames-on vs frames-off overhead at each rate:

```
[csd]# frames_sweep --runs 5 --rates 1,4,16 xz -T4 -k -f TestingData/testfile.bin
[csd]# analyze --frames 1
```

---

### Compare two programs natively

Time two programs head-to-head without PIN overhead (useful for before/after comparisons):

```
[csd]# compare --runs 20 ./pbz2-original -p4 -k -f TestingData/testfile.bin :: ./pbz2-padded -p4 -k -f TestingData/testfile.bin
```

---

### Reviewing saved runs

```
[csd]# logs        # list individual runs in logs/
[csd]# studies     # list study folders in studies/
```

To re-run `lookup` on an older run, pass its base path (tab-completion works):

```
[csd]# lookup logs/xz-20260609_143201
```

---

### Commands reference

| Command | Flags | Description |
|---|---|---|
| `run <prog> [args]` | `--frames 0\|1` | Instrument one run, stream output, save logs |
| `lookup [base]` | — | Resolve hotspot IPs → source file:line |
| `study <prog> [args]` | `--runs N` `--name NAME` `--frames 0\|1` | N repeated instrumented runs |
| `sweep <prog> [args]` | `--runs N` `--rates 1,2,…` `--frames 0\|1` | Run across multiple sample rates |
| `frames_sweep <prog> [args]` | `--runs N` `--rates 1,2,…` | Frames-on vs frames-off timing comparison |
| `compare <cmd1> :: <cmd2>` | `--runs N` | Native (no PIN) head-to-head timing |
| `analyze [folder]` | `--frames 0\|1` | Aggregate CSVs and produce plots |
| `logs` | — | List runs in `logs/` |
| `studies` | — | List study folders in `studies/` |
| `build` | — | Rebuild PIN tool, source_lookup, and venv |
| `help [command]` | — | Show help |
| `exit` | — | Exit |

## Build options

```bash
make tool          # rebuild PIN tool .so only
make source_lookup # rebuild source_lookup only
make benchmark     # compile test benchmarks
make clean         # remove build artifacts and logs
```

## Tested against

- **pbzip2** — parallel bzip2 compressor
- **xz** — parallel xz compressor
- Included `simple_benchmark` and `false_sharing_benchmark` for validation

Generate test data:

```bash
dd if=/dev/urandom of=TestingData/testfile.bin bs=1M count=20
```

## Output

Each run produces four files in `logs/`:

| File | Contents |
|---|---|
| `*-<timestamp>.log` | Human-readable sharing report with byte maps |
| `*-<timestamp>-ips.txt` | Raw IP dump for source_lookup |
| `*-<timestamp>-stats.csv` | Machine-readable data for analysis |
| `*-<timestamp>-lookup.txt` | Resolved source locations |

## Notes

- Instrumented programs run slower than native (PIN overhead). Expect 3-30× slowdown depending on memory access density.
- Source lookup requires debug symbols in the target binary (`-g` flag at compile time).
- For accurate call stack frames, build the target with `-fno-omit-frame-pointer`.
