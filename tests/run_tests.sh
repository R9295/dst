#!/usr/bin/env bash
set -euo pipefail

DETHV="./build/dethv"

echo "================================================================"
echo "1. Baseline: Prove nondet_torture IS non-deterministic on host OS"
echo "================================================================"
H1=$(./build/nondet_torture_dyn | grep FINAL_DIGEST)
H2=$(./build/nondet_torture_dyn | grep FINAL_DIGEST)
echo "  Host run 1: $H1"
echo "  Host run 2: $H2"
if [ "$H1" = "$H2" ]; then
    echo "ERROR: Expected host Linux runs to differ!"
    exit 1
fi
echo "  -> Confirmed: Native Linux is wildly non-deterministic!"

echo ""
echo "================================================================"
echo "2. DetHV Determinism Test: STATIC unmodified Linux binary (10x)"
echo "================================================================"
$DETHV --verify 10 --stats ./build/nondet_torture_static

echo ""
echo "================================================================"
echo "3. DetHV Determinism Test: DYNAMIC unmodified Linux binary (10x)"
echo "================================================================"
$DETHV --verify 10 --stats ./build/nondet_torture_dyn

echo ""
echo "================================================================"
echo "4. Seed Sensitivity Check: Different seeds -> different outputs"
echo "================================================================"
S1=$($DETHV --seed 0x1111 ./build/nondet_torture_static | grep FINAL_DIGEST)
S2=$($DETHV --seed 0x2222 ./build/nondet_torture_static | grep FINAL_DIGEST)
echo "  Seed 0x1111: $S1"
echo "  Seed 0x2222: $S2"
if [ "$S1" = "$S2" ]; then
    echo "ERROR: Different seeds produced identical digests!"
    exit 1
fi
echo "  -> Confirmed: Seed cleanly controls deterministic entropy!"

echo ""
echo "================================================================"
echo "5. Disk Snapshot Save & Reload Determinism (Fresh Process!)"
echo "================================================================"
SNAP_FILE="./build/test_snap.dhvs"
rm -f "$SNAP_FILE"
# Take snapshot at main() of nondet_torture_dyn, save to disk, and run to completion
OUT_A=$($DETHV --snap-sym main --save-snap "$SNAP_FILE" ./build/nondet_torture_dyn)
# Reload from disk snapshot in a completely fresh process!
OUT_B=$($DETHV --load-snap "$SNAP_FILE" ./build/nondet_torture_dyn)
OUT_C=$($DETHV --load-snap "$SNAP_FILE")
if [ "$OUT_A" != "$OUT_B" ] || [ "$OUT_A" != "$OUT_C" ]; then
    echo "ERROR: Disk snapshot reload diverged!"
    diff -u <(echo "$OUT_A") <(echo "$OUT_C") || true
    exit 1
fi
echo "  Snapshot file size: $(du -h "$SNAP_FILE" | cut -f1)"
echo "  Digest from fresh boot + snap : $(echo "$OUT_A" | grep FINAL_DIGEST)"
echo "  Digest from disk snap reload  : $(echo "$OUT_C" | grep FINAL_DIGEST)"
echo "  -> Confirmed: Disk snapshot reload is 100% BIT-FOR-BIT IDENTICAL!"

echo ""
echo "================================================================"
echo "6. Adversarial Multithreaded Snapshot Reload Torture (15x)"
echo "================================================================"
$DETHV --snap-sym main --bench-snap 15 ./build/nondet_torture_dyn

echo ""
echo "================================================================"
echo "7. Ultra-Fast Snapshot Reload Benchmark (50,000 resets, dynamic)"
echo "================================================================"
$DETHV --snap-on-stdin --stdin-str "HELLO_WORLD" --bench-snap 50000 ./build/fuzz_target_dyn

echo ""
echo "================================================================"
echo "8. Ultra-Fast Snapshot Reload Benchmark (50,000 resets, static)"
echo "================================================================"
$DETHV --snap-on-stdin --stdin-str "HELLO_WORLD" --bench-snap 50000 ./build/fuzz_target_static

echo ""
echo "================================================================"
echo "9. Deterministic Snapshot Fuzzing (100k execs, finds all 3 bugs)"
echo "================================================================"
$DETHV --snap-on-stdin --fuzz 100000 --fuzz-seed 0x1337 --fuzz-max-len 16 ./build/fuzz_target_dyn

echo ""
echo "ALL TESTS PASSED!"
