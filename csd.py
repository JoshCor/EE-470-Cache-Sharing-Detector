#!/usr/bin/env python3
"""
Cache Sharing Detector interactive shell.
Usage: ./csd.py
"""

import cmd
import os
import sys
import glob
import shlex
import subprocess
import readline
import time
from datetime import datetime

# --- path resolution ---
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
LOG_DIR       = os.path.join(SCRIPT_DIR, "logs")
STUDIES_DIR   = os.path.join(SCRIPT_DIR, "studies")
SOURCE_LOOKUP = os.path.join(SCRIPT_DIR, "source_lookup")
ANALYZE_PY    = os.path.join(SCRIPT_DIR, "analyze.py")
VENV_PYTHON   = os.path.join(SCRIPT_DIR, ".venv/bin/python3")

def _find_pin_root():
    if "PIN_ROOT" in os.environ:
        return os.environ["PIN_ROOT"]
    generic = os.path.expanduser("~/pin")
    if os.path.isdir(generic):
        return generic
    candidates = sorted(glob.glob(os.path.expanduser("~/pin-*/")))
    if candidates:
        return candidates[-1].rstrip("/")
    return os.path.expanduser("~/pin")

PIN_ROOT = _find_pin_root()
PIN      = os.path.join(PIN_ROOT, "pin")
TOOL     = os.path.join(PIN_ROOT, "source/tools/CacheSharingDetector"
                        "/obj-intel64/cache_sharing_detector.so")

# --- ANSI helpers ---
def _c(code, text): return f"\001{code}\002{text}\001\033[0m\002"
BOLD   = "\033[1m"; CYAN  = "\033[36m"; GREEN = "\033[32m"
YELLOW = "\033[33m"; RED  = "\033[31m"; RESET = "\033[0m"

def header(text): print(f"\n{BOLD}{text}{RESET}")
def ok(text):     print(f"  {GREEN}✓{RESET}  {text}")
def warn(text):   print(f"  {YELLOW}!{RESET}  {text}", file=sys.stderr)
def err(text):    print(f"  {RED}✗{RESET}  {text}", file=sys.stderr)


class CSD(cmd.Cmd):
    intro  = (f"\n{BOLD}Cache Sharing Detector{RESET}  —  "
              f"type {CYAN}help{RESET} for commands, "
              f"{CYAN}exit{RESET} to quit.\n")
    prompt = _c(CYAN, "[csd]") + "# "

    def __init__(self):
        super().__init__()
        self._last_base   = None   # base path for the most recent single run
        self._last_study  = None   # path of the most recently completed study folder
        for d in (LOG_DIR, STUDIES_DIR):
            os.makedirs(d, exist_ok=True)
        histfile = os.path.join(SCRIPT_DIR, ".csd_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        readline.set_history_length(500)
        self._histfile = histfile
        self._warn_missing()

    def _warn_missing(self):
        if not os.path.exists(PIN):
            warn(f"PIN not found at {PIN}")
            warn("Set PIN_ROOT env var or run: build")
        if not os.path.exists(TOOL):
            warn(f"PIN tool .so not built — run: build")
        if not os.path.exists(SOURCE_LOOKUP):
            warn(f"source_lookup not built — run: build")

    def postloop(self):
        try:
            readline.write_history_file(self._histfile)
        except Exception:
            pass

    # ------------------------------------------------------------------ run
    def do_run(self, line):
        """Run a program under PIN instrumentation.
  Usage:   run [--frames 0|1] [--sample-rate N] <program> [args...]
  Example: run --sample-rate 4 /path/to/pbzip2 -p4 -k -f TestingData/testfile.bin"""
        parts       = shlex.split(line)
        frames      = 1
        sample_rate = 1
        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--frames" and parts:
                try:
                    frames = int(parts.pop(0))
                except ValueError:
                    err("--frames requires 0 or 1"); return
            elif flag == "--sample-rate" and parts:
                try:
                    sample_rate = int(parts.pop(0))
                except ValueError:
                    err("--sample-rate requires an integer"); return
            else:
                err(f"Unknown flag: {flag}"); return
        if not parts:
            err("Usage: run [--frames 0|1] [--sample-rate N] <program> [args...]")
            return
        self._run_once(parts, LOG_DIR, sample_rate=sample_rate, frames=frames)

    def _check_paths(self):
        if not os.path.exists(PIN):
            err(f"PIN not found: {PIN}  (set PIN_ROOT or run: build)")
            return False
        if not os.path.exists(TOOL):
            err(f"Tool .so not found — run: build")
            return False
        return True

    def _run_once(self, cmd_parts, out_dir, run_label=None, sample_rate=1, frames=1):
        """Instrument one run, write all output files into out_dir. Returns base path."""
        if not self._check_paths():
            return None

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = run_label or os.path.basename(cmd_parts[0])[:30]
        base = os.path.join(out_dir, f"{slug}-{ts}")
        ips  = f"{base}-ips.txt"
        log  = f"{base}.log"

        pin_cmd = [PIN, "-t", TOOL,
                   "-ipdump", ips,
                   "-sample_rate", str(sample_rate),
                   "-frames", str(frames),
                   "--"] + cmd_parts
        print(f"  log  → {os.path.relpath(log)}")

        t0 = time.time()
        try:
            with open(log, "w") as logf:
                proc = subprocess.Popen(
                    pin_cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
                for out_line in proc.stdout:
                    sys.stdout.write(out_line)
                    logf.write(out_line)
                proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            warn("interrupted.")
            return None
        elapsed = time.time() - t0

        if proc.returncode != 0:
            warn(f"PIN exited {proc.returncode}")

        # write timing metadata alongside stats CSV
        meta = f"{base}-meta.csv"
        with open(meta, "w") as f:
            f.write("elapsed_s,sample_rate,frames\n")
            f.write(f"{elapsed:.2f},{sample_rate},{frames}\n")

        self._last_base = base
        return base

    def complete_run(self, text, line, begidx, endidx):
        return glob.glob(os.path.expanduser(text) + "*")

    # --------------------------------------------------------------- lookup
    def do_lookup(self, line):
        """Resolve hotspot IPs to source file:line with context.
  Usage:   lookup [base_path]
  Default: uses the most recent run."""
        if not os.path.exists(SOURCE_LOOKUP):
            err("source_lookup not built — run: build")
            return

        base = line.strip() if line.strip() else self._last_base
        if not base:
            err("No run loaded. Use 'run' first or supply a base path.")
            return

        ips = f"{base}-ips.txt"
        if not os.path.exists(ips):
            err(f"IPs file not found: {ips}")
            return

        header(f"lookup: {os.path.basename(base)}")
        result = subprocess.run([SOURCE_LOOKUP, ips], capture_output=True, text=True)
        print(result.stdout)

        out = f"{base}-lookup.txt"
        with open(out, "w") as f:
            f.write(result.stdout)
        ok(f"saved → {os.path.relpath(out)}")

    # --------------------------------------------------------- timing summary
    def _print_timing_summary(self, folder):
        import csv
        times = []
        for f in sorted(glob.glob(os.path.join(folder, "**/*-meta.csv"), recursive=True)):
            try:
                with open(f) as fh:
                    row = next(csv.DictReader(fh))
                    times.append(float(row["elapsed_s"]))
            except (StopIteration, KeyError, ValueError):
                pass
        if not times:
            return
        avg = sum(times) / len(times)
        mn  = min(times)
        mx  = max(times)
        print(f"\n  avg {avg:.2f}s  min {mn:.2f}s  max {mx:.2f}s  ({len(times)} runs)")

    # ---------------------------------------------------------------- study
    def do_study(self, line):
        """Run a program multiple times, saving all output to a single study folder.
  Usage:   study [--runs N] [--name NAME] [--frames 0|1] <program> [args...]
  Example: study --runs 20 --frames 0 /path/to/pbzip2 -p4 -k -f TestingData/testfile.bin"""
        parts  = shlex.split(line)
        runs   = 20
        name   = None
        frames = 1

        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--runs" and parts:
                try:
                    runs = int(parts.pop(0))
                except ValueError:
                    err("--runs requires an integer"); return
            elif flag == "--name" and parts:
                name = parts.pop(0)
            elif flag == "--frames" and parts:
                try:
                    frames = int(parts.pop(0))
                except ValueError:
                    err("--frames requires 0 or 1"); return
            else:
                err(f"Unknown flag: {flag}"); return

        if not parts:
            err("Usage: study [--runs N] [--name NAME] [--frames 0|1] <program> [args...]")
            return

        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{name or os.path.basename(parts[0])}-{ts}"
        study_dir   = os.path.join(STUDIES_DIR, folder_name)
        os.makedirs(study_dir)

        header(f"study: {runs} runs → {os.path.relpath(study_dir)}/")
        completed = 0
        for i in range(1, runs + 1):
            print(f"\n{BOLD}--- run {i}/{runs} ---{RESET}")
            base = self._run_once(parts, study_dir, run_label=f"run{i:02d}", frames=frames)
            if base and os.path.exists(f"{base}-ips.txt"):
                with open(f"{base}-lookup.txt", "w") as lf:
                    subprocess.run([SOURCE_LOOKUP, f"{base}-ips.txt"],
                                   stdout=lf, stderr=subprocess.DEVNULL)
                completed += 1

        self._last_study = study_dir
        ok(f"study done: {completed}/{runs} runs in {os.path.relpath(study_dir)}/")
        self._print_timing_summary(study_dir)

    complete_study = complete_run

    # ---------------------------------------------------------------- sweep
    def do_sweep(self, line):
        """Run a sample-rate sweep (1,2,4,8,16 by default), N runs per rate.
  All results saved in one timestamped sweep folder.
  Usage:   sweep [--runs N] [--rates 1,2,4,8,16] [--frames 0|1] <program> [args...]
  Example: sweep --runs 5 --frames 0 /path/to/pbzip2 -p4 -k -f TestingData/testfile.bin"""
        parts  = shlex.split(line)
        runs   = 5
        rates  = [1, 2, 4, 8, 16]
        frames = 1

        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--runs" and parts:
                try:
                    runs = int(parts.pop(0))
                except ValueError:
                    err("--runs requires an integer"); return
            elif flag == "--rates" and parts:
                try:
                    rates = [int(r) for r in parts.pop(0).split(",")]
                except ValueError:
                    err("--rates requires comma-separated integers"); return
            elif flag == "--frames" and parts:
                try:
                    frames = int(parts.pop(0))
                except ValueError:
                    err("--frames requires 0 or 1"); return
            else:
                err(f"Unknown flag: {flag}"); return

        if not parts:
            err("Usage: sweep [--runs N] [--rates 1,2,4,8,16] [--frames 0|1] <program> [args...]")
            return

        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        sweep_dir  = os.path.join(STUDIES_DIR, f"sweep-{os.path.basename(parts[0])}-{ts}")
        os.makedirs(sweep_dir)

        header(f"sweep: rates={rates}, {runs} runs each → {os.path.relpath(sweep_dir)}/")
        for sr in rates:
            rate_dir = os.path.join(sweep_dir, f"sr{sr}")
            os.makedirs(rate_dir)
            print(f"\n{BOLD}=== sample_rate={sr} ==={RESET}")
            completed = 0
            for i in range(1, runs + 1):
                print(f"\n{BOLD}--- run {i}/{runs} ---{RESET}")
                base = self._run_once(parts, rate_dir,
                                      run_label=f"run{i:02d}", sample_rate=sr,
                                      frames=frames)
                if base and os.path.exists(f"{base}-ips.txt"):
                    with open(f"{base}-lookup.txt", "w") as lf:
                        subprocess.run([SOURCE_LOOKUP, f"{base}-ips.txt"],
                                       stdout=lf, stderr=subprocess.DEVNULL)
                    completed += 1

            ok(f"sr{sr}: {completed}/{runs} runs done")

        self._last_study = sweep_dir
        ok(f"sweep complete → {os.path.relpath(sweep_dir)}/")

    complete_sweep = complete_run

    # ----------------------------------------------------------- frames_sweep
    def do_frames_sweep(self, line):
        """Run a frames-on vs frames-off timing comparison across sample rates.
  Usage:   frames_sweep [--runs N] [--rates 1,2,4,8,16] <program> [args...]
  Example: frames_sweep --runs 5 /path/to/pbzip2 -p4 -k -f TestingData/testfile.bin"""
        parts = shlex.split(line)
        runs  = 5
        rates = [1, 2, 4, 8, 16]

        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--runs" and parts:
                try:
                    runs = int(parts.pop(0))
                except ValueError:
                    err("--runs requires an integer"); return
            elif flag == "--rates" and parts:
                try:
                    rates = [int(r) for r in parts.pop(0).split(",")]
                except ValueError:
                    err("--rates requires comma-separated integers"); return
            else:
                err(f"Unknown flag: {flag}"); return

        if not parts:
            err("Usage: frames_sweep [--runs N] [--rates 1,2,4,8,16] <program> [args...]")
            return

        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        sweep_dir = os.path.join(STUDIES_DIR,
                                 f"frames-sweep-{os.path.basename(parts[0])}-{ts}")
        os.makedirs(sweep_dir)

        header(f"frames_sweep: rates={rates}, {runs} runs × 2 modes → {os.path.relpath(sweep_dir)}/")
        for sr in rates:
            for frames in [1, 0]:
                rate_dir = os.path.join(sweep_dir, f"sr{sr}-f{frames}")
                os.makedirs(rate_dir)
                print(f"\n{BOLD}=== sample_rate={sr}, frames={frames} ==={RESET}")
                completed = 0
                for i in range(1, runs + 1):
                    print(f"\n{BOLD}--- run {i}/{runs} ---{RESET}")
                    base = self._run_once(parts, rate_dir,
                                          run_label=f"run{i:02d}",
                                          sample_rate=sr,
                                          frames=frames)
                    if base and os.path.exists(f"{base}-ips.txt"):
                        with open(f"{base}-lookup.txt", "w") as lf:
                            subprocess.run([SOURCE_LOOKUP, f"{base}-ips.txt"],
                                           stdout=lf, stderr=subprocess.DEVNULL)
                        completed += 1
                ok(f"sr{sr}-f{frames}: {completed}/{runs} runs done")

        self._last_study = sweep_dir
        ok(f"frames sweep complete → {os.path.relpath(sweep_dir)}/")

    complete_frames_sweep = complete_run

    # --------------------------------------------------------------- compare
    def do_compare(self, line):
        """Run two programs natively (no PIN) and compare timing over N runs.
  Usage:   compare [--runs N] <cmd1> :: <cmd2>
  Example: compare --runs 20 /path/to/pbz2 -p4 -k -f file.bin :: ./pbz2-padded -p4 -k -f file.bin"""
        parts = shlex.split(line)
        runs  = 20

        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--runs" and parts:
                try:
                    runs = int(parts.pop(0))
                except ValueError:
                    err("--runs requires an integer"); return
            else:
                err(f"Unknown flag: {flag}"); return

        try:
            sep = parts.index("::")
        except ValueError:
            err("Missing '::' separator between the two commands"); return

        cmd1, cmd2 = parts[:sep], parts[sep+1:]
        if not cmd1 or not cmd2:
            err("Both commands must be non-empty"); return

        name1 = os.path.basename(cmd1[0])
        name2 = os.path.basename(cmd2[0])
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        study_dir = os.path.join(STUDIES_DIR, f"compare-{name1}-{ts}")
        for name in (name1, name2):
            os.makedirs(os.path.join(study_dir, name))

        header(f"compare: {runs} runs × 2 programs → {os.path.relpath(study_dir)}/")
        for i in range(1, runs + 1):
            for name, cmd in ((name1, cmd1), (name2, cmd2)):
                out_dir = os.path.join(study_dir, name)
                ts_run  = datetime.now().strftime("%Y%m%d_%H%M%S")
                base    = os.path.join(out_dir, f"run{i:02d}-{ts_run}")
                print(f"\n{BOLD}--- {name} run {i}/{runs} ---{RESET}")
                t0 = time.time()
                try:
                    with open(f"{base}.log", "w") as logf:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT, text=True)
                        for out_line in proc.stdout:
                            sys.stdout.write(out_line)
                            logf.write(out_line)
                        proc.wait()
                except KeyboardInterrupt:
                    proc.terminate()
                    warn("interrupted."); return
                elapsed = time.time() - t0
                with open(f"{base}-meta.csv", "w") as f:
                    f.write("elapsed_s\n")
                    f.write(f"{elapsed:.2f}\n")
                ok(f"{elapsed:.1f}s")

        self._last_study = study_dir
        ok(f"compare done → {os.path.relpath(study_dir)}/")

    complete_compare = complete_run

    # --------------------------------------------------------------- analyze
    def do_analyze(self, line):
        """Aggregate a study folder and produce plots.
  Usage:   analyze [--frames 0|1] [study_folder]
  Default: uses the most recent study.
  --frames: extract one side of a frames_sweep as a regular sweep."""
        if not os.path.exists(ANALYZE_PY):
            err(f"analyze.py not found: {ANALYZE_PY}")
            return

        parts  = shlex.split(line)
        frames = None
        while parts and parts[0].startswith("--"):
            flag = parts.pop(0)
            if flag == "--frames" and parts:
                frames = parts.pop(0)
            else:
                err(f"Unknown flag: {flag}"); return

        target = parts[0] if parts else self._last_study
        if not target:
            studies = sorted(glob.glob(os.path.join(STUDIES_DIR, "*/")))
            if not studies:
                err("No studies found. Run 'study' first.")
                return
            target = studies[-1].rstrip("/")

        if not os.path.isdir(target):
            err(f"Study folder not found: {target}")
            return

        py  = VENV_PYTHON if os.path.exists(VENV_PYTHON) else "python3"
        cmd = [py, ANALYZE_PY, target]
        if frames is not None:
            cmd += ["--frames", frames]
        header(f"analyze: {os.path.relpath(target)}/")
        subprocess.run(cmd)

    # --------------------------------------------------------------- studies
    def do_studies(self, line):
        """List saved study folders.
  Usage: studies"""
        folders = sorted(glob.glob(os.path.join(STUDIES_DIR, "*/")))
        if not folders:
            warn("No studies yet — run 'study' to create one.")
            return
        header(f"studies  ({len(folders)} total)")
        for f in folders:
            name  = os.path.basename(f.rstrip("/"))
            runs  = len(glob.glob(os.path.join(f, "*-stats.csv")))
            print(f"  {name}  [{runs} runs]")
        if self._last_study:
            print(f"\n  current: {CYAN}{os.path.basename(self._last_study)}{RESET}")

    # ------------------------------------------------------------------ logs
    def do_logs(self, line):
        """List individual (non-study) runs in logs/.
  Usage: logs"""
        stats = sorted(glob.glob(os.path.join(LOG_DIR, "*-stats.csv")))
        if not stats:
            warn("No runs in logs/ yet.")
            return
        header(f"runs  ({len(stats)} total)")
        for f in stats:
            base = f[:-len("-stats.csv")]
            name = os.path.basename(base)
            tags = []
            if os.path.exists(f"{base}-lookup.txt"):
                tags.append(f"{GREEN}lookup{RESET}")
            suffix = f"  [{', '.join(tags)}]" if tags else ""
            print(f"  {name}{suffix}")
        if self._last_base:
            print(f"\n  current: {CYAN}{os.path.basename(self._last_base)}{RESET}")

    # ----------------------------------------------------------------- build
    def do_build(self, line):
        """Build or rebuild all binaries (PIN tool, source_lookup, venv).
  Usage: build"""
        header("build")
        ret = subprocess.run(["make", "-C", SCRIPT_DIR, "tool",
                              "source_lookup", ".venv/bin/python3"]).returncode
        if ret == 0:
            ok("build complete")
        else:
            err("build failed — check output above")

    # ----------------------------------------------------------------- clean
    def do_clean(self, line):
        """Remove all build artifacts (binaries, venv, plots).
  Does NOT delete study or log data.
  Usage: clean"""
        header("clean")
        subprocess.run(["make", "-C", SCRIPT_DIR, "clean-build"])
        ok("build artifacts removed")

    # ----------------------------------------------------------------- exit
    def do_exit(self, line):
        """Exit the session."""
        print("Bye.")
        return True

    do_quit = do_exit

    def do_EOF(self, line):
        print()
        return self.do_exit(line)

    def emptyline(self):
        pass


if __name__ == "__main__":
    try:
        CSD().cmdloop()
    except KeyboardInterrupt:
        print("\nBye.")
