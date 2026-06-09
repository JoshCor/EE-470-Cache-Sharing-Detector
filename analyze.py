#!/usr/bin/env python3
# Usage: python3 analyze.py <study_folder_or_sweep_folder>
#
# Regular study:  studies/pbz2-20260531_120000/
#   → plots/study.png
#
# Sweep folder:   studies/sweep-pbz2-20260531_120000/   (contains sr1/, sr2/, ...)
#   → plots/sweep.png

import sys
import os
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

PLOT_DIR = "plots"
os.makedirs(PLOT_DIR, exist_ok=True)

# Known target lines in the instrumented binary that indicate correct detection.
# Format: just filename:line (no full path — matched by endswith).
TARGET_LINES = ["pbzip2.cpp:2587", "pbzip2.cpp:1738"]

# ------------------------------------------------------------------ loaders

def load_study(folder):
    """Load all *-stats.csv and *-meta.csv from a flat study folder.
    Returns a DataFrame with a 'run' column (0-based index)."""
    stats_files = sorted(glob.glob(os.path.join(folder, "*-stats.csv")))
    if not stats_files:
        return pd.DataFrame()
    dfs = []
    for i, f in enumerate(stats_files):
        df = pd.read_csv(f)
        df["run"] = i
        # attach elapsed_s if meta file exists
        meta_f = f.replace("-stats.csv", "-meta.csv")
        if os.path.exists(meta_f):
            meta = pd.read_csv(meta_f)
            df["elapsed_s"] = meta["elapsed_s"].iloc[0]
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def load_sweep(sweep_folder):
    """Load all sr*/ subdirectories. Returns a DataFrame with 'sr' column."""
    rate_dirs = sorted(glob.glob(os.path.join(sweep_folder, "sr*/")),
                       key=lambda p: int(os.path.basename(p.rstrip("/"))[2:]))
    if not rate_dirs:
        return pd.DataFrame()
    dfs = []
    for rd in rate_dirs:
        sr = int(os.path.basename(rd.rstrip("/"))[2:])
        df = load_study(rd)
        if df.empty:
            continue
        df["sr"] = sr
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def load_lookup_hits(folder):
    """Parse *-lookup.txt files. Returns DataFrame: run, location, hit_count."""
    import re
    rows = []
    for i, f in enumerate(sorted(glob.glob(os.path.join(folder, "*-lookup.txt")))):
        in_table = False
        with open(f, errors="replace") as lf:
            for line in lf:
                clean = re.sub(r'\033\[[0-9;]*[mK]', '', line)  # strip ANSI
                if clean.startswith("hits"):
                    in_table = True; continue
                if in_table and clean.startswith("------"):
                    continue
                if in_table:
                    if not clean.strip() or clean.strip().startswith("="):
                        break
                    # format: "%-6d  %-5s  %-14s  %s" — split on whitespace max 3 times
                    # so location (which may contain spaces) is captured whole
                    parts = clean.split(None, 3)
                    if len(parts) == 4:
                        try:
                            rows.append({"run": i,
                                         "hit_count": int(parts[0]),
                                         "location": parts[3].strip()})
                        except ValueError:
                            pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["run", "hit_count", "location"])


def count_binary_ips(folder):
    """Count unique IPs belonging to the main binary (first image) per run.
    Returns DataFrame: run, unique_binary_ips."""
    rows = []
    for i, f in enumerate(sorted(glob.glob(os.path.join(folder, "*-ips.txt")))):
        binary_lo, binary_hi = None, None
        unique = set()
        with open(f, errors="replace") as ipf:
            bases = []
            lines = ipf.readlines()
            for line in lines:
                if not line.startswith("image:"): break
                last = line.rstrip().rsplit(":", 1)
                if len(last) == 2:
                    try: bases.append(int(last[1], 16))
                    except ValueError: pass
            if len(bases) >= 1:
                binary_lo = bases[0]
                binary_hi = bases[1] if len(bases) >= 2 else bases[0] + 0x10000000
            if binary_lo is None:
                rows.append({"run": i, "unique_binary_ips": 0}); continue
            for line in lines:
                if line.startswith("image:"): continue
                parts = line.split()
                for tok in parts[2:]:            # skip type and tid
                    try:
                        ip = int(tok, 16)
                        if binary_lo <= ip < binary_hi:
                            unique.add(ip)
                    except ValueError:
                        pass
        rows.append({"run": i, "unique_binary_ips": len(unique)})
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["run", "unique_binary_ips"])


def is_frames_sweep(folder):
    return bool(glob.glob(os.path.join(folder, "sr*-f*/")))

def is_sweep(folder):
    return bool(glob.glob(os.path.join(folder, "sr*/"))) and not is_frames_sweep(folder)


def label_roles(data):
    group_cols = ["sr", "run", "rank"] if "sr" in data.columns else ["run", "rank"]
    max_w = data.groupby(group_cols)["writes"].transform("max")
    data["role"] = np.where(data["writes"] == max_w, "worker", "coordinator")
    return data


def mask_to_bits(hex_str):
    v = int(hex_str, 16)
    return np.array([(v >> b) & 1 for b in range(64)], dtype=np.float32)

# ---------------------------------------------------------------- study plot

def plot_study(data, folder):
    data = label_roles(data)
    data["write_bits"] = data["write_mask"].apply(mask_to_bits)
    data["read_bits"]  = data["read_mask"].apply(mask_to_bits)

    n_runs = data["run"].nunique()
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f"Cache Sharing Detector — {os.path.basename(folder)}  ({n_runs} runs)",
                 fontsize=13, fontweight="bold")

    # 1: hotspot count per run
    ax = axes[0, 0]
    counts = data.groupby("run")["rank"].max()
    ax.bar(counts.index + 1, counts.values, color="steelblue", edgecolor="white")
    ax.set_xlabel("Run"); ax.set_ylabel("Hotspots detected")
    ax.set_title("Hotspot count per run")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # 2: worker write count by rank
    ax = axes[0, 1]
    workers = data[data["role"] == "worker"]
    ranks   = sorted(workers["rank"].unique())
    bp = ax.boxplot([workers[workers["rank"] == r]["writes"].values for r in ranks],
                    labels=[f"Rank {r}" for r in ranks], patch_artist=True)
    for p in bp["boxes"]: p.set_facecolor("steelblue"); p.set_alpha(0.7)
    ax.set_ylabel("Writes per run"); ax.set_title("Worker write count by hotspot rank")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x/1e6:.1f}M"))

    # 3: sharing type frequency
    ax = axes[1, 0]
    per_hs = data.drop_duplicates(["run", "rank"])
    tc = per_hs["sharing"].value_counts()
    short = (tc.index.str.replace("_sharing","",regex=False)
               .str.replace("producer_consumer","prod-con",regex=False)
               .str.replace("|","+",regex=False))
    ax.bar(range(len(tc)), tc.values, color="steelblue", edgecolor="white")
    ax.set_xticks(range(len(tc)))
    ax.set_xticklabels(short, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Occurrences"); ax.set_title("Sharing type frequency")

    # 4: byte heatmap
    ax = axes[1, 1]
    wr = data[data["role"] == "worker"]
    hm = np.vstack([np.vstack(wr["write_bits"].values).mean(axis=0),
                    np.vstack(wr["read_bits"].values).mean(axis=0)])
    im = ax.imshow(hm, aspect="auto", cmap="YlOrRd", vmin=0, vmax=1)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Write", "Read"])
    ax.set_xlabel("Byte offset within cache line")
    ax.set_title("Avg byte access frequency — worker threads")
    for x in range(8, 64, 8): ax.axvline(x - 0.5, color="white", linewidth=0.8)
    plt.colorbar(im, ax=ax, label="Fraction of accesses")

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "study.png")
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")

    print(f"\n--- Summary ({n_runs} runs) ---")
    counts_vals = data.groupby("run")["rank"].max()
    print(f"Hotspots/run: {counts_vals.mean():.1f} avg (min {counts_vals.min()}, max {counts_vals.max()})")
    for r in ranks:
        w = workers[workers["rank"] == r]["writes"]
        print(f"  Rank {r}: mean={w.mean()/1e6:.2f}M  std={w.std()/1e6:.2f}M")

# ----------------------------------------------------------------- sweep plot

def plot_sweep(data, folder):
    data = label_roles(data)
    rates = sorted(data["sr"].unique())
    n_runs = data.groupby("sr")["run"].nunique().min()

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f"Sample Rate Sweep — {os.path.basename(folder)}", fontsize=13, fontweight="bold")

    COLORS = plt.cm.Blues(np.linspace(0.4, 0.9, len(rates)))

    # 1: hotspot count by sample rate (box plot)
    ax = axes[0, 0]
    hc_data = [data[data["sr"] == sr].groupby("run")["rank"].max().values for sr in rates]
    bp = ax.boxplot(hc_data, tick_labels=[f"SR={r}" for r in rates], patch_artist=True)
    for patch, c in zip(bp["boxes"], COLORS): patch.set_facecolor(c)
    ax.set_ylabel("Hotspots detected per run")
    ax.set_title("Hotspot detection vs sample rate")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # 2: write count scaling (normalized to SR=1)
    ax = axes[0, 1]
    workers = data[data["role"] == "worker"]
    baseline = workers[workers["sr"] == 1].groupby("run")["writes"].sum().mean()
    means, stds = [], []
    for sr in rates:
        w = workers[workers["sr"] == sr].groupby("run")["writes"].sum()
        means.append(w.mean() / baseline)
        stds.append(w.std() / baseline)
    ax.bar(range(len(rates)), means, yerr=stds, color=COLORS, edgecolor="white", capsize=4)
    # expected: 1/SR line
    ax.plot(range(len(rates)), [1/sr for sr in rates], "r--o", markersize=4,
            label="expected (1/SR)")
    ax.set_xticks(range(len(rates)))
    ax.set_xticklabels([f"SR={r}" for r in rates])
    ax.set_ylabel("Write count (normalized to SR=1)")
    ax.set_title("Write count scaling vs sample rate")
    ax.legend(fontsize=8)

    # 3: sharing type consistency
    ax = axes[1, 0]
    per_hs = data.drop_duplicates(["sr", "run", "rank"])
    all_types = per_hs["sharing"].unique()
    x = np.arange(len(rates))
    bottoms = np.zeros(len(rates))
    type_colors = plt.cm.Set2(np.linspace(0, 1, len(all_types)))
    for t, c in zip(all_types, type_colors):
        counts = [per_hs[(per_hs["sr"] == sr) & (per_hs["sharing"] == t)].shape[0]
                  for sr in rates]
        short = (t.replace("_sharing", "").replace("producer_consumer", "prod-con")
                  .replace("|", "+"))
        ax.bar(x, counts, bottom=bottoms, color=c, label=short, edgecolor="white")
        bottoms += np.array(counts, dtype=float)
    ax.set_xticks(x); ax.set_xticklabels([f"SR={r}" for r in rates])
    ax.set_ylabel("Hotspot count (all runs)")
    ax.set_title("Sharing type distribution by sample rate")
    ax.legend(fontsize=8, loc="upper right")

    # 4: elapsed time by sample rate
    ax = axes[1, 1]
    if "elapsed_s" in data.columns:
        elapsed_data = [data[data["sr"] == sr].drop_duplicates(["sr", "run"])["elapsed_s"].values
                        for sr in rates]
        bp = ax.boxplot(elapsed_data, tick_labels=[f"SR={r}" for r in rates], patch_artist=True)
        for patch, c in zip(bp["boxes"], COLORS): patch.set_facecolor(c)
        ax.set_ylabel("Elapsed time (s)")
        ax.set_title("Run time vs sample rate")
    else:
        ax.text(0.5, 0.5, "No timing data\n(run via csd.py sweep)",
                ha="center", va="center", transform=ax.transAxes, fontsize=11)
        ax.set_title("Run time vs sample rate")

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "sweep.png")
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")

    print(f"\n--- Sweep Summary ---")
    for sr in rates:
        d = workers[workers["sr"] == sr]
        hc = data[data["sr"] == sr].groupby("run")["rank"].max()
        wc = d.groupby("run")["writes"].sum()
        print(f"  SR={sr:2d}:  hotspots={hc.mean():.1f}  "
              f"writes={wc.mean()/1e6:.1f}M  "
              f"(~{wc.mean()/baseline:.2f}x baseline)")

# --------------------------------------------------------- ip analysis (sweep)

def plot_ip_analysis(sweep_folder):
    """Separate 2-plot figure: raw binary IP capture and correct-location detection."""
    rate_dirs = sorted(glob.glob(os.path.join(sweep_folder, "sr*/")),
                       key=lambda p: int(os.path.basename(p.rstrip("/"))[2:]))
    rates = [int(os.path.basename(p.rstrip("/"))[2:]) for p in rate_dirs]

    # collect per-rate data
    ip_counts   = []   # list of arrays (one per rate): unique binary IPs per run
    detect_rate = []   # fraction of runs that found ALL target lines per rate

    for rd in rate_dirs:
        bip = count_binary_ips(rd)
        ip_counts.append(bip["unique_binary_ips"].values if not bip.empty else np.array([0]))

        lkp = load_lookup_hits(rd)
        if lkp.empty:
            detect_rate.append(0.0)
            continue
        n_runs = lkp["run"].nunique()
        hits = 0
        for run_id in lkp["run"].unique():
            run_locs = set(lkp[lkp["run"] == run_id]["location"].apply(
                lambda loc: next((t for t in TARGET_LINES
                                  if loc.endswith(t)), None)
            ).dropna())
            if all(t in run_locs for t in TARGET_LINES):
                hits += 1
        detect_rate.append(hits / n_runs if n_runs > 0 else 0.0)

    COLORS = plt.cm.Blues(np.linspace(0.4, 0.9, len(rates)))

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(f"IP Capture Analysis — {os.path.basename(sweep_folder)}",
                 fontsize=13, fontweight="bold")

    # Plot 1: unique binary IPs per run (box plot)
    ax = axes[0]
    bp = ax.boxplot(ip_counts, tick_labels=[f"SR={r}" for r in rates],
                    patch_artist=True)
    for patch, c in zip(bp["boxes"], COLORS):
        patch.set_facecolor(c)
    ax.set_ylabel("Unique IPs in main binary captured")
    ax.set_title("Raw binary IP capture vs sample rate")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Plot 2: correct-location detection rate
    ax = axes[1]
    bars = ax.bar(range(len(rates)), [r * 100 for r in detect_rate],
                  color=COLORS, edgecolor="white")
    ax.set_xticks(range(len(rates)))
    ax.set_xticklabels([f"SR={r}" for r in rates])
    ax.set_ylabel("Runs detecting both target lines (%)")
    ax.set_ylim(0, 110)
    ax.set_title(f"Correct location detection\n({' and '.join(TARGET_LINES)})")
    for bar, val in zip(bars, detect_rate):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                f"{val*100:.0f}%", ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "ip_analysis.png")
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")

    print("\n--- IP Analysis Summary ---")
    for r, ips, dr in zip(rates, ip_counts, detect_rate):
        print(f"  SR={r:2d}:  binary IPs={np.mean(ips):.1f} avg  "
              f"target detection={dr*100:.0f}%")

# ------------------------------------------------------- frames sweep plot

def load_frames_sweep(sweep_folder):
    """Load all sr*-f*/ subdirs. Returns DataFrame with 'sr' and 'frames' columns."""
    rate_dirs = sorted(glob.glob(os.path.join(sweep_folder, "sr*-f*/")),
                       key=lambda p: (int(os.path.basename(p.rstrip("/")).split("-f")[0][2:]),
                                      int(os.path.basename(p.rstrip("/")).split("-f")[1])))
    if not rate_dirs:
        return pd.DataFrame()
    dfs = []
    for rd in rate_dirs:
        name   = os.path.basename(rd.rstrip("/"))
        sr     = int(name.split("-f")[0][2:])
        frames = int(name.split("-f")[1])
        df = load_study(rd)
        if df.empty:
            continue
        df["sr"]     = sr
        df["frames"] = frames
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def plot_frames_sweep(data, folder):
    rates  = sorted(data["sr"].unique())
    x      = np.arange(len(rates))
    width  = 0.35
    COLORS = {"frames_on": "#4C9BE8", "frames_off": "#E8844C"}

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.suptitle(f"Frame Capture Timing — {os.path.basename(folder)}",
                 fontsize=13, fontweight="bold")

    for col, (frames_val, label) in enumerate([(1, "frames on"), (0, "frames off")]):
        subset = data[data["frames"] == frames_val]
        means, errs = [], []
        for sr in rates:
            t = subset[subset["sr"] == sr].drop_duplicates(["sr", "frames", "run"])["elapsed_s"]
            means.append(t.mean() if not t.empty else 0)
            errs.append(t.std()   if not t.empty else 0)
        offset = (col - 0.5) * width
        color  = COLORS["frames_on"] if frames_val else COLORS["frames_off"]
        bars   = ax.bar(x + offset, means, width, yerr=errs, label=label,
                        color=color, capsize=4, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels([f"SR={r}" for r in rates])
    ax.set_ylabel("Elapsed time (s)")
    ax.set_xlabel("Sample rate")
    ax.legend()
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:.1f}s"))

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "frames_sweep.png")
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")

    print("\n--- Frames Sweep Summary ---")
    for sr in rates:
        t_on  = data[(data["sr"] == sr) & (data["frames"] == 1)].drop_duplicates(["sr","frames","run"])["elapsed_s"]
        t_off = data[(data["sr"] == sr) & (data["frames"] == 0)].drop_duplicates(["sr","frames","run"])["elapsed_s"]
        if not t_on.empty and not t_off.empty:
            delta = t_on.mean() - t_off.mean()
            print(f"  SR={sr:2d}:  frames_on={t_on.mean():.2f}s  frames_off={t_off.mean():.2f}s  "
                  f"delta={delta:+.2f}s")

# ----------------------------------------------------------- native compare plot

def is_compare(folder):
    subdirs = [d for d in glob.glob(os.path.join(folder, "*/"))
               if not os.path.basename(d.rstrip("/")).startswith("sr")]
    return bool(subdirs) and any(
        glob.glob(os.path.join(d, "*-meta.csv")) for d in subdirs)


def load_compare(folder):
    subdirs = sorted([d for d in glob.glob(os.path.join(folder, "*/"))
                      if not os.path.basename(d.rstrip("/")).startswith("sr")])
    rows = []
    for d in subdirs:
        name = os.path.basename(d.rstrip("/"))
        for i, m in enumerate(sorted(glob.glob(os.path.join(d, "*-meta.csv")))):
            meta = pd.read_csv(m)
            rows.append({"run": i, "name": name, "elapsed_s": meta["elapsed_s"].iloc[0]})
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def plot_compare(data, folder):
    names  = list(data["name"].unique())
    COLORS = ["#4C9BE8", "#E8844C"]

    fig, ax = plt.subplots(figsize=(7, 5))
    fig.suptitle(f"Native Runtime Comparison — {os.path.basename(folder)}",
                 fontsize=13, fontweight="bold")

    bp = ax.boxplot([data[data["name"] == n]["elapsed_s"].values for n in names],
                    tick_labels=names, patch_artist=True, widths=0.5)
    for patch, c in zip(bp["boxes"], COLORS):
        patch.set_facecolor(c); patch.set_alpha(0.75)

    for i, n in enumerate(names):
        ys = data[data["name"] == n]["elapsed_s"].values
        ax.scatter(np.full(len(ys), i + 1) + np.random.uniform(-0.08, 0.08, len(ys)),
                   ys, color=COLORS[i], s=18, zorder=3, alpha=0.85)

    ax.set_ylabel("Elapsed time (s)")
    ax.set_title("20 runs each, no PIN instrumentation")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:.1f}s"))

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "compare.png")
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")

    print("\n--- Compare Summary ---")
    for n in names:
        t = data[data["name"] == n]["elapsed_s"]
        print(f"  {n}: mean={t.mean():.2f}s  std={t.std():.2f}s  "
              f"min={t.min():.2f}s  max={t.max():.2f}s")
    if len(names) == 2:
        t0 = data[data["name"] == names[0]]["elapsed_s"]
        t1 = data[data["name"] == names[1]]["elapsed_s"]
        print(f"\n  speedup ({names[1]} vs {names[0]}): {t0.mean()/t1.mean():.3f}x")

# ----------------------------------------------------------------------- main

def _parse_args():
    import argparse
    p = argparse.ArgumentParser(
        description="Analyze CSD study / sweep / frames-sweep folders.")
    p.add_argument("folder")
    p.add_argument("--frames", type=int, choices=[0, 1], default=None,
                   help="For a frames_sweep folder: extract only this frames value "
                        "and produce sweep plots (0=off, 1=on).")
    return p.parse_args()


def load_frames_sweep_as_sweep(sweep_folder, frames_val):
    """Extract sr*-fN dirs from a frames_sweep and load as a regular sweep."""
    pattern = os.path.join(sweep_folder, f"sr*-f{frames_val}/")
    rate_dirs = sorted(glob.glob(pattern),
                       key=lambda p: int(os.path.basename(p.rstrip("/")).split("-f")[0][2:]))
    if not rate_dirs:
        return pd.DataFrame(), []
    dfs  = []
    virt = os.path.join(sweep_folder, f"_virtual_sr_f{frames_val}")
    os.makedirs(virt, exist_ok=True)
    sr_dirs = []
    for rd in rate_dirs:
        sr   = int(os.path.basename(rd.rstrip("/")).split("-f")[0][2:])
        df   = load_study(rd)
        if df.empty:
            continue
        df["sr"] = sr
        dfs.append(df)
        # symlink so plot_ip_analysis can find sr*/ subdirs
        link = os.path.join(virt, f"sr{sr}")
        if not os.path.exists(link):
            os.symlink(os.path.abspath(rd), link)
        sr_dirs.append(link)
    return (pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()), virt


if __name__ == "__main__":
    args   = _parse_args()
    folder = args.folder.rstrip("/")
    if not os.path.isdir(folder):
        print(f"Not a directory: {folder}")
        sys.exit(1)

    if is_frames_sweep(folder):
        if args.frames is not None:
            print(f"Extracting frames={args.frames} from frames_sweep: {folder}")
            data, virt = load_frames_sweep_as_sweep(folder, args.frames)
            if data.empty:
                print("No data found."); sys.exit(1)
            plot_sweep(data, folder)
            plot_ip_analysis(virt)
        else:
            print(f"Detected frames sweep folder: {folder}")
            data = load_frames_sweep(folder)
            if data.empty:
                print("No data found."); sys.exit(1)
            plot_frames_sweep(data, folder)
    elif is_compare(folder):
        print(f"Detected compare folder: {folder}")
        data = load_compare(folder)
        if data.empty:
            print("No data found."); sys.exit(1)
        plot_compare(data, folder)
    elif is_sweep(folder):
        print(f"Detected sweep folder: {folder}")
        data = load_sweep(folder)
        if data.empty:
            print("No data found."); sys.exit(1)
        plot_sweep(data, folder)
        plot_ip_analysis(folder)
    else:
        print(f"Detected study folder: {folder}")
        data = load_study(folder)
        if data.empty:
            print("No *-stats.csv files found."); sys.exit(1)
        plot_study(data, folder)
