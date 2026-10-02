'''
Zeroization-by-reset tests for the shaman SHA256 core.

The design uses a synchronous reset (Amaranth: rst = ~rst_n, sampled on
posedge clk).  These tests check that, after reset, no state derived from a
previously processed (secret) message survives anywhere in the design.

The check is differential: every signal inside the DUT instance is
snapshotted after a reset that follows secret processing, and compared with a
snapshot taken after a reset from a clean state, under identical inputs.  Any
difference is a residue of the secret.

Run with:  make MODULE=test_zeroize
'''

import os

import cocotb
from cocotb.clock import Clock
from cocotb.handle import (HierarchyArrayObject, HierarchyObject,
                           NonHierarchyIndexableObject, NonHierarchyObject,
                           ConstantObject, ModifiableObject)
from cocotb.triggers import ClockCycles, Timer

from test import loadMessageBlock, message_to_blocks, processMessageBlocks

GateLevelTest = os.environ.get('GATES') == 'yes'

# two unrelated secrets, so a residue cannot coincidentally look clean
SecretA = bytes(range(0x80, 0x80 + 64)) * 2 + b'TOP SECRET KEY MATERIAL'
SecretB = b'\xa5\x5a' * 70 + b'another secret, different length'

CLK_PERIOD_US = 10


def snapshot(handle, prefix='', out=None):
    '''Recursively read every signal below handle: {name: bitstring}.'''
    if out is None:
        out = {}
    for child in handle:
        name = prefix + child._name
        if name.endswith('clk'):
            continue
        if isinstance(child, (ModifiableObject, ConstantObject)):
            out[name] = child.value.binstr
        elif isinstance(child, NonHierarchyIndexableObject):
            left, right = child._range  # iterate by declared index, not position
            step = 1 if right >= left else -1
            for i in range(left, right + step, step):
                out[f'{name}[{i}]'] = child[i].value.binstr
        elif isinstance(child, (HierarchyObject, HierarchyArrayObject)):
            snapshot(child, name + '.', out)
        elif isinstance(child, NonHierarchyObject):
            out[name] = str(child.value)
    return out


def bits_match(clean, dirty):
    # A bit that is x/z in the clean run matches anything.  This only happens
    # on combinational nets (always @*) that Icarus never evaluated because
    # their inputs never changed after power-on; every register in the design
    # has an initial value, so storage is never x in the clean run.
    return len(clean) == len(dirty) and all(
        c in 'xXzZ' or c == d for c, d in zip(clean, dirty))


def diff(clean, dirty):
    return sorted(k for k in clean if not bits_match(clean[k], dirty.get(k, '')))


def assert_same(dut, clean, dirty, what):
    bad = diff(clean, dirty)
    for k in bad[:20]:
        dut._log.error(f'{what}: residue in {k}: clean={clean[k][:64]} after={dirty[k][:64]}')
    assert not bad, f'{what}: {len(bad)} signal(s) differ from a clean reset'
    wild = sum(1 for v in clean.values() if any(c in 'xXzZ' for c in v))
    dut._log.info(f'{what}: {len(clean)} signals identical to clean reset '
                  f'({wild} unevaluated combinational nets ignored)')


def idle_inputs(dut):
    dut.ena.value = 1
    dut.databyteIn.value = 0
    dut.parallelLoading.value = 0
    dut.resultNext.value = 0
    dut.start.value = 0
    dut.clockinData.value = 0


async def reset_and_snapshot(dut, cycles=10):
    '''Assert reset with idle inputs; snapshot during and after reset.'''
    idle_inputs(dut)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, cycles)
    await Timer(1, units='ns')  # let the edge's register updates settle
    during = snapshot(dut.tt_um_psychogenic_shaman)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)
    await Timer(1, units='ns')
    after = snapshot(dut.tt_um_psychogenic_shaman)
    return during, after


async def start_clean(dut):
    clock = Clock(dut.clk, CLK_PERIOD_US, units='us')
    clk_task = cocotb.start_soon(clock.start())
    golden = await reset_and_snapshot(dut)
    return clk_task, golden


async def begin_message(dut):
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    dut.start.value = 1
    await ClockCycles(dut.clk, 1)
    dut.start.value = 0
    await ClockCycles(dut.clk, 1)


async def read_result_bytes(dut):
    '''Read the 32 result bytes through the external interface.'''
    out = []
    for _ in range(32):
        out.append(int(dut.resultbyteOut.value))
        dut.resultNext.value = 1
        await ClockCycles(dut.clk, 2)
        dut.resultNext.value = 0
        await ClockCycles(dut.clk, 1)
    return bytes(out)


async def check_reset(dut, golden, what, cycles=10):
    during, after = await reset_and_snapshot(dut, cycles)
    assert_same(dut, golden[0], during, f'{what} (reset held)')
    assert_same(dut, golden[1], after, f'{what} (reset released)')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_after_complete_hash(dut):
    '''Secret fully hashed and its digest read out.'''
    _, golden = await start_clean(dut)
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretA, message_to_blocks(SecretA))
    assert dut.resultReady.value == 1
    await check_reset(dut, golden, 'complete hash')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_after_partial_readout(dut):
    '''Digest partially read out (resultIndex mid-way).'''
    _, golden = await start_clean(dut)
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretB, message_to_blocks(SecretB))
    for _ in range(13):
        dut.resultNext.value = 1
        await ClockCycles(dut.clk, 2)
        dut.resultNext.value = 0
        await ClockCycles(dut.clk, 1)
    await check_reset(dut, golden, 'partial readout')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_mid_load(dut):
    '''Reset while a block is half loaded into the input buffer.'''
    _, golden = await start_clean(dut)
    await begin_message(dut)
    await loadMessageBlock(dut, message_to_blocks(SecretA)[0][:32])
    await check_reset(dut, golden, 'mid-load')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_mid_compression(dut):
    '''Reset while the compression rounds are running (busy).'''
    _, golden = await start_clean(dut)
    await begin_message(dut)
    await loadMessageBlock(dut, message_to_blocks(SecretA)[0])
    for _ in range(100):
        if dut.processingReceivedDataBlock.value == 1:
            break
        await ClockCycles(dut.clk, 1)
    await ClockCycles(dut.clk, 150)
    assert dut.processingReceivedDataBlock.value == 1, 'not mid-compression'
    await check_reset(dut, golden, 'mid-compression')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_single_cycle_reset(dut):
    '''Minimum reset: rst_n low for exactly one rising clock edge.'''
    _, golden = await start_clean(dut)
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretA, message_to_blocks(SecretA))
    await check_reset(dut, golden, 'single-cycle reset', cycles=1)


@cocotb.test(skip=GateLevelTest)
async def test_reset_needs_clock(dut):
    '''Characterization: synchronous reset does nothing while clk is stopped.'''
    clk_task, golden = await start_clean(dut)
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretA, message_to_blocks(SecretA))
    before = snapshot(dut.tt_um_psychogenic_shaman)

    clk_task.kill()
    dut.clk.value = 0
    idle_inputs(dut)
    dut.rst_n.value = 0
    await Timer(100 * CLK_PERIOD_US, units='us')
    held = snapshot(dut.tt_um_psychogenic_shaman)
    state = [k for k in before if k.endswith(('hbuf0', 'apibuf', 'wt_buf'))]
    kept = [k for k in state if held[k] == before[k] and '1' in before[k]]
    dut._log.warning(f'clock stopped, rst_n low: {len(kept)}/{len(state)} '
                     f'secret-bearing registers still hold data: {kept}')
    assert kept, 'expected synchronous reset to need a clock edge'

    # a single clock edge with rst_n low clears it
    dut.clk.value = 1
    await Timer(CLK_PERIOD_US / 2, units='us')
    dut.clk.value = 0
    await Timer(CLK_PERIOD_US / 2, units='us')
    assert_same(dut, golden[0], snapshot(dut.tt_um_psychogenic_shaman),
                'after one clock edge')


@cocotb.test(skip=GateLevelTest)
async def test_no_digest_leak_and_reuse_after_reset(dut):
    '''After reset the interface shows no digest, and the core hashes correctly.'''
    import hashlib
    await start_clean(dut)
    clean_readout = await read_result_bytes(dut)
    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretA, message_to_blocks(SecretA))

    idle_inputs(dut)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)

    # resultReady is ~(beginProcessingDataBlock | processingReceivedDataBlock),
    # i.e. high whenever idle, so it is not a leak indicator; the bytes are.
    leaked = await read_result_bytes(dut)
    assert leaked == clean_readout == bytes(32), f'digest readable after reset: {leaked.hex()}'
    assert leaked != hashlib.sha256(SecretA).digest()

    dut.parallelLoading.value = 1
    await ClockCycles(dut.clk, 2)
    await processMessageBlocks(dut, SecretB, message_to_blocks(SecretB))
