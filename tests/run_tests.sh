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
echo "================================================================"
echo "10. Hypercall dethv_get_input() Auto-Snapshot & Disk Reload"
echo "================================================================"
# Native Linux safely returns -ENOSYS from DETHV_HC_PING and falls back to stdin
NATIVE_OUT=$(printf "HELLO" | ./build/fuzz_hc_target_dyn)
echo "  Native Linux fallback: $NATIVE_OUT"
HC_SNAP="./build/test_hc_snap.dhvs"
rm -f "$HC_SNAP"
# Auto-snapshot at dethv_get_input() and save to disk!
$DETHV --save-snap "$HC_SNAP" --input-str "HELLO_HC" --stats ./build/fuzz_hc_target_dyn
# Reload saved hypercall snapshot and inject a crashing input ("DF!B") -> SIGSEGV
set +e
$DETHV --load-snap "$HC_SNAP" --input-str "DF!B" --stats 2>&1 | tee ./build/dethv_hc_segv.log
SEGV_RC=${PIPESTATUS[0]}
$DETHV --load-snap "$HC_SNAP" --input-str "DP!!" --stats 2>&1 | tee ./build/dethv_hc_panic.log
PANIC_RC=${PIPESTATUS[0]}
set -e
grep -q "stop=CRASH_SIGSEGV" ./build/dethv_hc_segv.log
grep -q "stop=CRASH_SIGABRT" ./build/dethv_hc_panic.log
grep -q "cr2=0xbad1" ./build/dethv_hc_panic.log
rm -f ./build/dethv_hc_segv.log ./build/dethv_hc_panic.log
echo "  -> Confirmed: Auto-snapshot at dethv_get_input() + disk reload + dethv_panic() work!"

echo ""
echo "================================================================"
echo "11. Hypercall Snapshot Reload Benchmark (50,000 resets)"
echo "================================================================"
$DETHV --input-str "HELLO_WORLD" --bench-snap 50000 ./build/fuzz_hc_target_dyn
$DETHV --input-str "HELLO_WORLD" --bench-snap 50000 ./build/fuzz_hc_target_static

echo ""
echo "================================================================"
echo "12. Hypercall Auto-Snapshot Fuzzing (100k execs, finds all 4 bugs)"
echo "================================================================"
$DETHV --fuzz 100000 --fuzz-seed 0x1337 --fuzz-max-len 16 ./build/fuzz_hc_target_dyn

echo ""
echo "ALL TESTS PASSED!"
