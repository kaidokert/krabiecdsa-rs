#!/usr/bin/env python3
"""Build and run krabiecdsa examples on QEMU for all Cortex-M targets.

Generates a markdown metrics table from the results.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

EXAMPLES = [
    # (example, backend, variant, [features])
    ("baseline",     "baseline", "baseline", ["baseline"]),
    ("ecdsa_verify", "u8",       "p256",     ["curve_p256", "limb_u8"]),
    ("ecdsa_verify", "u32",      "p256",     ["curve_p256", "limb_u32"]),
    ("ecdsa_verify", "u8",       "k256",     ["curve_k256", "limb_u8"]),
    ("ecdsa_verify", "u32",      "k256",     ["curve_k256", "limb_u32"]),
    ("ecdsa_verify", "u8",       "p384",     ["curve_p384", "limb_u8"]),
    ("ecdsa_verify", "u32",      "p384",     ["curve_p384", "limb_u32"]),
]
# Variant -> (curve label, hash label) in render order.
KEY_VARIANTS = [
    ("p256", "P-256",     "sha256"),
    ("k256", "secp256k1", "sha256"),
    ("p384", "P-384",     "sha384"),
]
TARGETS = [
    ("thumbv6m-none-eabi", "M0"),
    ("thumbv7m-none-eabi", "M3"),
    ("thumbv7em-none-eabi", "M4"),
]
TIMEOUT_RUN = 300  # seconds per QEMU run (4096-bit can take a while)
TIMEOUT_BUILD = 600  # seconds for cargo build
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(tempfile.gettempdir(), "krabiecdsa_footprint_cortexm")


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", TARGET_DIR)
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=SCRIPT_DIR,
        env=env,
        **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build_examples(target, features):
    """Build all examples for a target. Returns True on success."""
    args = ["cargo", "build", "--target", target, "--release", "--examples"]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, _out, err = run_cmd(
        args,
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print(f"BUILD FAILED for {target}:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example, features):
    """Run an example on QEMU via cargo run. Returns stdout+stderr."""
    args = ["cargo", "run", "--target", target, "--release", "--example", example]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, out, err = run_cmd(
        args
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"    cargo run failed (rc={rc}):", file=sys.stderr)
        print(combined, file=sys.stderr)
    return combined


def get_text_size(target, example, features):
    """Get .text section size via cargo-bloat JSON output."""
    try:
        args = [
            "cargo", "bloat", "--release", "--target", target,
            "--example", example, "--message-format=json",
        ]
        if features:
            args.extend(["--features", ",".join(features)])
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            json_line = out.strip().split("\n")[-1]
            data = json.loads(json_line)
            return data.get("text-section-size")
        else:
            print(f"    cargo-bloat failed (rc={rc}): {err.strip()}", file=sys.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    cargo-bloat not available: {e}", file=sys.stderr)
    except (json.JSONDecodeError, IndexError) as e:
        print(f"    cargo-bloat JSON parse error: {e}", file=sys.stderr)
    return None


def parse_metric(output):
    """Parse METRIC line from QEMU output. Returns dict or None."""
    m = re.search(
        r"METRIC stack:(\d+) cycles:(\d+) target:(\S+) backend:(\S+)", output
    )
    if m:
        return {
            "stack": int(m.group(1)),
            "cycles": int(m.group(2)),
            "target": m.group(3),
            "backend": m.group(4),
        }
    return None


def delta(verify_row, baseline_row, key, formatter=str):
    verify_value = verify_row.get(key)
    baseline_value = baseline_row.get(key)
    if verify_value is None or baseline_value is None:
        return "-"
    return formatter(verify_value - baseline_value)


def main():
    results = {}  # (backend, variant, target) -> {stack, cycles, text_size, accepted}
    failures = []

    for target, label in TARGETS:
        print(f"Running examples for {target}...", file=sys.stderr)
        for example, backend, variant, features in EXAMPLES:
            key = (backend, variant, target)
            feat_str = ",".join(features) if features else "no-features"
            print(f"  {example} [{feat_str}] on {label}...", file=sys.stderr)
            try:
                # cargo run rebuilds with the specified features. Each
                # (example, features) combo produces a fresh binary at the
                # same path, so we run+size for each combo in sequence.
                output = run_qemu(target, example, features)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} [{feat_str}] on {label}")
                continue

            accepted = "ecdsa ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example, features)

            if not metric:
                print("    METRIC line missing", file=sys.stderr)
                failures.append(f"Missing METRIC: {example} [{feat_str}] on {label}")
            if text_size is None:
                print("    .text size unavailable", file=sys.stderr)
                failures.append(f"Missing .text size: {example} [{feat_str}] on {label}")

            results[key] = {
                "accepted": accepted,
                "backend": backend,
                "variant": variant,
                "stack": metric["stack"] if metric else None,
                "cycles": metric["cycles"] if metric else None,
                "text_size": text_size,
            }

            status = "ACCEPT" if accepted else "REJECT"
            print(f"    {status}", file=sys.stderr)
            if not accepted:
                failures.append(f"REJECT: {example} [{feat_str}] on {label}")

    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate cycle cost of ECDSA verification.")
    print()
    print("| Target | Curve | Hash | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|-------|------|---------|-------------|---------------|-------------------|")
    for target, label in TARGETS:
        baseline_row = results.get(("baseline", "baseline", target))
        for variant, key_label, hash_label in KEY_VARIANTS:
            for backend in ("u8", "u32"):
                verify_row = results.get((backend, variant, target))
                if verify_row is None or baseline_row is None:
                    print(f"| {label} | {key_label} | {hash_label} | {backend} | - | - | - |")
                    continue
                delta_text = delta(
                    verify_row,
                    baseline_row,
                    "text_size",
                    formatter=lambda value: f"{value / 1024:.1f}",
                )
                delta_stack = delta(verify_row, baseline_row, "stack")
                delta_cycles = delta(verify_row, baseline_row, "cycles")
                print(f"| {label} | {key_label} | {hash_label} | {backend} | {delta_text} | {delta_stack} | {delta_cycles} |")

    print()
    print("Approx cycles are derived from the demo harness counters and should be treated as a rough instruction-cost proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures (shown as `-` in table): {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
