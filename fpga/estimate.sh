#!/usr/bin/env bash
# FPGA resource and Fmax estimates for this design.
#
#   1. Yosys synth_intel_alm for Cyclone V: LUT / register counts.  Yosys
#      reports unpacked LUT cells, not ALMs, and gives no Fmax.
#   2. Yosys + nextpnr place-and-route on Lattice ECP5 (LFE5U-25F) and
#      iCE40 (HX8K), one run per seed: Fmax and utilisation.  These are
#      relative indicators only; Cyclone V timing must come from Quartus.
#
# Usage:   fpga/estimate.sh            (from anywhere)
# Options: SEEDS="1 2 3" FREQ=50 fpga/estimate.sh
# Needs:   yosys, nextpnr-ecp5, nextpnr-ice40 (missing nextpnr targets are skipped)
#          e.g. apt-get install yosys nextpnr-ecp5 nextpnr-ice40
# Output:  fpga/build/ (logs, netlists) and fpga/build/summary.txt

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../src/tt_um_psychogenic_shaman.v"
TOP=tt_um_psychogenic_shaman
SEEDS="${SEEDS:-1 2 3}"
FREQ="${FREQ:-50}"
OUT="$HERE/build"

command -v yosys >/dev/null || { echo "yosys not found" >&2; exit 1; }
mkdir -p "$OUT"
cd "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
say() { echo "$*" | tee -a "$SUMMARY"; }

say "design: $TOP ($(basename "$SRC"))"
say "yosys:  $(yosys -V)"
say ""

# --- Cyclone V cell counts -------------------------------------------------
yosys -q -l cyclonev.log -p "read_verilog $SRC; synth_intel_alm -family cyclonev -top $TOP; stat" >/dev/null
say "Cyclone V (synth_intel_alm, unpacked cells):"
awk '/Printing statistics/{p=1} p && /MISTRAL_(ALUT|FF)/{n[$1]=$2} END{
  lut=0; for (k in n) if (k ~ /ALUT[2-6]$/) lut+=n[k]
  printf "  LUT (ALUT2-6): %d\n  arithmetic:    %d\n  registers:     %d\n", lut, n["MISTRAL_ALUT_ARITH"], n["MISTRAL_FF"]
}' cyclonev.log | tee -a "$SUMMARY"
say ""

# --- nextpnr Fmax ------------------------------------------------------------
fmax() { grep "Max frequency for clock" "$1" | tail -1 | sed -E 's/.*: ([0-9.]+) MHz.*/\1/'; }

pnr() {  # $1 = arch name, $2 = synth command, $3.. = nextpnr command
  local arch=$1 synth=$2; shift 2
  if ! command -v "$1" >/dev/null; then
    say "$arch: $1 not found, skipped"; say ""; return
  fi
  yosys -q -l "${arch}_synth.log" -p "read_verilog $SRC; $synth -top $TOP -json $arch.json" >/dev/null
  local results=()
  for seed in $SEEDS; do
    if "$@" --json "$arch.json" --freq "$FREQ" --seed "$seed" --timing-allow-fail \
         --log "${arch}_s$seed.log" >/dev/null 2>&1; then
      results+=("$(fmax "${arch}_s$seed.log")")
    else
      results+=("fail")
    fi
  done
  say "$arch Fmax (MHz) per seed [$SEEDS]: ${results[*]}"
  { printf '%s\n' "${results[@]}" | grep -v fail || true; } | sort -n | head -1 | sed 's/^/  minimum: /' | tee -a "$SUMMARY"
  local first=(${SEEDS})
  grep -E "(TRELLIS_COMB|TRELLIS_FF|ICESTORM_LC|MULT18X18D|DP16KD|ICESTORM_RAM):" \
    "${arch}_s${first[0]}.log" 2>/dev/null | tail -4 | sed -E 's/^Info:[[:space:]]+/  /' | tee -a "$SUMMARY" || true
  say ""
}

pnr ecp5  synth_ecp5  nextpnr-ecp5  --25k --package CABGA256
pnr ice40 synth_ice40 nextpnr-ice40 --hx8k --package ct256 --pcf-allow-unconstrained

say "I/O pins are unconstrained; Fmax is nextpnr's register-to-register figure."
say "Logs: $OUT"
