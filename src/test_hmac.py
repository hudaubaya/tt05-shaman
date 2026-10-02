'''
HMAC-SHA256 usage of the shaman core: single-cycle reset zeroization while
K^ipad is being compressed, and cycle-accurate latency of a full HMAC.

The core only computes SHA256; HMAC is driven by the host as two hashes:
    inner = SHA256((K ^ ipad) || msg)
    outer = SHA256((K ^ opad) || inner)
For a message of up to 55 bytes each hash is two 64-byte blocks, so one HMAC
is four blocks plus two 32-byte digest readouts.

Default byte protocol (the same as test.py): clockinData high 2 cycles + low
1 cycle per byte, resultNext high 2 cycles + low 1 cycle per digest byte.
test_strobe_width_sweep characterizes 1-cycle strobes: they work when the host
samples busy/resultbyteOut after the clock edge (as a synchronous host does),
and fail when it samples the pre-edge value as test.py does.

Run with:  make MODULE=test_hmac
'''

import hashlib
import hmac
import os
import re

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

from test import message_to_blocks
from test_zeroize import idle_inputs, snapshot

GateLevelTest = os.environ.get('GATES') == 'yes'

CLK_PERIOD_NS = 20  # 50 MHz, a typical Cyclone V board clock; cycles are what matter

KEY = bytes.fromhex('0b1c2d3e4f5061728394a5b6c7d8e9fa') * 2  # 32-byte key
MSG = b'authenticate me: nonce=8f3a21c0'

# Instance path inside tt_um_psychogenic_shaman for each Amaranth module.
INSTANCE_PATH = {
    'shapi': 'shapi',
    'blockproc': 'shapi.blockproc',
    't1': 'shapi.blockproc.t1',
    'wt': 'shapi.blockproc.t1.wt',
}

# Registers the proposal names explicitly; all must exist and read zero.
NAMED_STATE = (
    ['shapi.apibuf', 'shapi.blockproc_bp_initdat', 'shapi.resultbyteOut']
    + [f'shapi.blockproc.bp_{c}' for c in 'abcdefgh']
    + [f'shapi.blockproc.hbuf{i}' for i in range(8)]
    + [f'shapi.blockproc.t1.wt.sbuf-{i}' for i in range(1, 16)]
)


def all_registers():
    '''Every flip-flop in the RTL, as snapshot keys (parsed from the Verilog).'''
    src = open(os.path.join(os.path.dirname(__file__), 'tt_um_psychogenic_shaman.v')).read()
    regs = []
    for body in re.split(r'\n(?=module )', src):
        m = re.match(r'module (\S+)\(', body)
        if not m or m.group(1) not in INSTANCE_PATH:
            continue
        for name in re.findall(r'always @\(posedge clk\)\s*(\S+)\s*<=', body):
            regs.append(f'{INSTANCE_PATH[m.group(1)]}.{name.lstrip(chr(92))}')
    return regs


def hmac_blocks(key, msg):
    k = key.ljust(64, b'\0')
    ipad = bytes(b ^ 0x36 for b in k)
    opad = bytes(b ^ 0x5c for b in k)
    return ipad, opad


class Cycles:
    '''Free-running rising-edge counter.'''

    def __init__(self, dut):
        self.n = 0
        cocotb.start_soon(self._run(dut))

    async def _run(self, dut):
        while True:
            await RisingEdge(dut.clk)
            self.n += 1


# Host-side strobe widths in clock cycles.  The defaults are test.py's
# protocol; test_strobe_width_sweep tries shorter ones.
# settle=True samples busy/resultbyteOut 1 ns after the clock edge (the value
# a synchronous host register would capture); settle=False samples at the
# edge itself, i.e. the pre-edge value, one cycle stale (test.py's behaviour).
# jitter=N adds 0..N random idle cycles after each data byte, to exercise
# many alignments of the strobe against the core's internal state.
DEFAULT_TIMING = dict(data_high=2, data_low=1, read_pre=2, read_high=2, read_low=1,
                      settle=False, jitter=0)
_jitter_rng = __import__('random').Random(99)
TIMING = dict(DEFAULT_TIMING)


async def settle():
    if TIMING['settle']:
        await Timer(1, units='ns')


async def strobe_byte(dut, value):
    await settle()
    while dut.busy.value:
        await ClockCycles(dut.clk, 1)
        await settle()
    dut.databyteIn.value = value
    dut.clockinData.value = 1
    await ClockCycles(dut.clk, TIMING['data_high'])
    dut.clockinData.value = 0
    await ClockCycles(dut.clk, TIMING['data_low'])
    if TIMING['jitter']:
        extra = _jitter_rng.randint(0, TIMING['jitter'])
        if extra:
            await ClockCycles(dut.clk, extra)


async def load_block(dut, block, cyc=None):
    '''Load one 64-byte block; return cycle at the last byte's strobe.'''
    last_strobe = None
    for i, b in enumerate(block):
        if i == len(block) - 1:
            await settle()
            while dut.busy.value:
                await ClockCycles(dut.clk, 1)
                await settle()
            last_strobe = cyc.n if cyc else None
        await strobe_byte(dut, b)
    return last_strobe


async def wait_block_done(dut):
    '''resultReady = ~(beginProcessingDataBlock | processingReceivedDataBlock):
    it is high when idle, so wait for it to drop and rise again.'''
    for _ in range(1000):
        if not dut.resultReady.value:
            break
        await ClockCycles(dut.clk, 1)
    else:
        raise AssertionError('block processing never started')
    for _ in range(2000):
        if dut.resultReady.value:
            return
        await ClockCycles(dut.clk, 1)
    raise AssertionError('block processing never finished')


async def start_message(dut):
    dut.parallelLoading.value = 1
    dut.start.value = 1
    await ClockCycles(dut.clk, 1)
    dut.start.value = 0
    await ClockCycles(dut.clk, 1)


async def read_digest(dut):
    if TIMING['read_pre']:
        await ClockCycles(dut.clk, TIMING['read_pre'])  # test.py: 1 causes skipped bytes
    out = []
    for _ in range(32):
        await settle()
        out.append(int(dut.resultbyteOut.value))
        dut.resultNext.value = 1
        await ClockCycles(dut.clk, TIMING['read_high'])
        dut.resultNext.value = 0
        await ClockCycles(dut.clk, TIMING['read_low'])
    return bytes(out)


async def sha256_on_core(dut, data, cyc=None, log=None, pipelined=False):
    '''pipelined: start loading the next block without waiting for the
    previous one to finish (the loader still stalls on busy).'''
    await start_message(dut)
    blocks = message_to_blocks(data)
    for idx, block in enumerate(blocks):
        t_load = cyc.n if cyc else 0
        last = await load_block(dut, bytes(block), cyc)
        if pipelined and idx < len(blocks) - 1:
            if cyc and log is not None:
                log.append((idx, last - t_load, None))
            continue
        await wait_block_done(dut)
        if cyc and log is not None:
            log.append((idx, last - t_load, cyc.n - last))
    t0 = cyc.n if cyc else 0
    digest = await read_digest(dut)
    if cyc and log is not None:
        log.append(('readout', cyc.n - t0))
    return digest


async def hmac_on_core(dut, key, msg, cyc=None, log=None, pipelined=False):
    ipad, opad = hmac_blocks(key, msg)
    inner = await sha256_on_core(dut, ipad + msg, cyc, log, pipelined)
    return await sha256_on_core(dut, opad + inner, cyc, log, pipelined)


async def power_on(dut):
    '''Clean reset; return the snapshot one cycle after rst_n is released.'''
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    idle_inputs(dut)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    golden = snapshot(dut.tt_um_psychogenic_shaman)
    await ClockCycles(dut.clk, 10)
    return golden


@cocotb.test(skip=GateLevelTest)
async def test_single_cycle_reset_mid_ipad(dut):
    '''rst_n low for exactly one clock edge while K^ipad is being compressed
    clears every register; a following HMAC is still correct.'''
    golden = await power_on(dut)
    regs = all_registers()
    assert len(regs) == 61, f'expected 61 flip-flops in the RTL, found {len(regs)}'
    missing = [r for r in NAMED_STATE if r not in regs]
    assert not missing, f'named state registers not found: {missing}'

    ipad, _ = hmac_blocks(KEY, MSG)
    await start_message(dut)
    await load_block(dut, ipad)
    for _ in range(100):
        if dut.processingReceivedDataBlock.value:
            break
        await ClockCycles(dut.clk, 1)
    await ClockCycles(dut.clk, 200)
    assert dut.processingReceivedDataBlock.value, 'not mid-compression'

    before = snapshot(dut.tt_um_psychogenic_shaman)
    loaded = [r for r in regs if '1' in before[r]]
    dut._log.info(f'{len(loaded)}/{len(regs)} registers hold non-zero data before reset')
    for r in ('shapi.blockproc.bp_initdat', 'shapi.blockproc.bp_a',
              'shapi.blockproc.t1.wt.wt_buf', 'shapi.blockproc.t1.wt.sbuf-1'):
        assert '1' in before[r], f'{r} unexpectedly zero before reset'

    # exactly one rising edge with rst_n low
    idle_inputs(dut)
    dut.rst_n.value = 0
    await RisingEdge(dut.clk)
    dut.rst_n.value = 1
    await Timer(1, units='ns')
    after = snapshot(dut.tt_um_psychogenic_shaman)
    nonzero = [r for r in regs if after[r].strip('0')]
    for r in nonzero:
        dut._log.error(f'not zero after 1-cycle reset: {r} = {after[r][:64]}')
    assert not nonzero, f'{len(nonzero)} register(s) not zeroized'
    dut._log.info(f'all {len(regs)} registers zero on the cycle after a 1-cycle reset '
                  f'({len(NAMED_STATE)} named in the proposal)')

    # One cycle after release the idle state machines leave zero (e.g.
    # bp_procst); that must match a clean reset exactly, bit for bit.
    await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    after2 = snapshot(dut.tt_um_psychogenic_shaman)
    moved = [r for r in regs if after2[r].strip('0')]
    differ = [r for r in regs if after2[r] != golden[r]]
    dut._log.info(f'one cycle after release, non-zero (idle control state): '
                  + ', '.join(f'{r}={after2[r]}' for r in moved))
    assert not differ, f'differs from a clean reset one cycle after release: {differ}'
    assert not any(r in moved for r in NAMED_STATE)

    mac = await hmac_on_core(dut, KEY, MSG)
    expected = hmac.new(KEY, MSG, hashlib.sha256).digest()
    dut._log.info(f'HMAC after reset: core={mac.hex()} ref={expected.hex()}')
    assert mac == expected


async def measure_hmac(dut, pipelined):
    await power_on(dut)
    cyc = Cycles(dut)
    log = []
    t0 = cyc.n
    mac = await hmac_on_core(dut, KEY, MSG, cyc, log, pipelined)
    total = cyc.n - t0
    assert mac == hmac.new(KEY, MSG, hashlib.sha256).digest()

    blocks = [e for e in log if e[0] != 'readout']
    reads = [e[1] for e in log if e[0] == 'readout']
    for n, (idx, load, proc) in enumerate(blocks):
        dut._log.info(f'block {n} (hash {n // 2}, block {idx}): load-to-last-strobe {load} cycles, '
                      f'last strobe -> resultReady {proc} cycles')
    for r in reads:
        dut._log.info(f'digest readout: {r} cycles')
    mhz = 1000 / CLK_PERIOD_NS
    mode = 'pipelined' if pipelined else 'serial'
    dut._log.info(f'HMAC total ({mode}): {total} cycles = {total / mhz:.2f} us at {mhz:.0f} MHz')
    dut._log.info('LATENCY ' + repr({'mode': mode, 'blocks': blocks, 'readouts': reads, 'total': total}))


@cocotb.test(skip=GateLevelTest)
async def test_hmac_latency_cycles(dut):
    '''Cycle counts for one HMAC-SHA256 (4 blocks, 2 digest readouts),
    each block fully processed before the next is loaded.'''
    await measure_hmac(dut, pipelined=False)


@cocotb.test(skip=GateLevelTest)
async def test_hmac_latency_cycles_pipelined(dut):
    '''Same, loading the next block while the previous one is processed.'''
    await measure_hmac(dut, pipelined=True)


async def reset_core(dut):
    idle_inputs(dut)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 2)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


STROBE_CONFIGS = [
    # name, data_high, data_low, read_pre, read_high, read_low, settle
    ('baseline 2+1 / 2+1', 2, 1, 2, 2, 1, False),
    ('data 1+1 / read 2+1', 1, 1, 2, 2, 1, False),
    ('data 1+1 / read 1+1', 1, 1, 2, 1, 1, False),
    ('settled 2+1 / 2+1', 2, 1, 2, 2, 1, True),
    ('settled data 1+1 / read 2+1', 1, 1, 2, 2, 1, True),
    ('settled data 1+1 / read 1+1', 1, 1, 2, 1, 1, True),
    ('settled 1+1 / 1+1, pre 1', 1, 1, 1, 1, 1, True),
    ('settled 1+1 / 1+1, pre 0', 1, 1, 0, 1, 1, True),
    ('settled 1+1 / 1+1, jitter 0-3', 1, 1, 0, 1, 1, True, 3),
]
SWEEP_RUNS = int(os.environ.get('SWEEP_RUNS', '5'))


@cocotb.test(skip=GateLevelTest)
async def test_strobe_width_sweep(dut):
    '''HMAC cycle count and correctness for shorter host strobes.

    Each configuration runs SWEEP_RUNS HMACs with random keys (1-64 bytes) and
    messages (0-55 bytes, so always 4 blocks), serial and pipelined.  A lost
    or duplicated byte shows up as a wrong MAC or a processing timeout.
    Characterization only: it fails only if the baseline protocol fails.'''
    import random
    rng = random.Random(1234)
    await power_on(dut)
    cyc = Cycles(dut)
    results = []
    try:
        for name, dh, dl, rp, rh, rl, st, *jit in STROBE_CONFIGS:
            TIMING.update(data_high=dh, data_low=dl, read_pre=rp, read_high=rh, read_low=rl,
                          settle=st, jitter=jit[0] if jit else 0)
            for pipelined in (False, True):
                ok, counts, errors = 0, [], []
                for _ in range(SWEEP_RUNS):
                    key = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
                    msg = bytes(rng.randrange(256) for _ in range(rng.randint(0, 55)))
                    await reset_core(dut)
                    t0 = cyc.n
                    try:
                        mac = await hmac_on_core(dut, key, msg, pipelined=pipelined)
                    except AssertionError as e:
                        errors.append(f'timeout ({e})')
                        continue
                    if mac == hmac.new(key, msg, hashlib.sha256).digest():
                        ok += 1
                        counts.append(cyc.n - t0)
                    else:
                        errors.append('wrong MAC')
                mode = 'pipelined' if pipelined else 'serial'
                rng_txt = f'{min(counts)}-{max(counts)}' if counts else 'n/a'
                dut._log.info(f'SWEEP {name:30s} {mode:9s}: {ok}/{SWEEP_RUNS} correct, '
                              f'cycles {rng_txt}' + (f', failures: {sorted(set(errors))}' if errors else ''))
                results.append((name, mode, ok, counts))
    finally:
        TIMING.update(DEFAULT_TIMING)
    for name, mode, ok, _ in results:
        if name.startswith('baseline'):
            assert ok == SWEEP_RUNS, f'baseline protocol failed ({mode})'
