'''
Tests for hmac_ctrl.v driving the shaman core (tb_hmac.v).

Run with:  make HMAC=yes
'''

import hashlib
import hmac
import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

from test_hmac import all_registers
from test_zeroize import snapshot

GateLevelTest = os.environ.get('GATES') == 'yes'

KEY_BYTES = 32
MAX_MSG_BYTES = 55
CLK_PERIOD_NS = 20

# RFC 4231 test cases whose key and data fit (TC5 is truncated output, TC6/7
# use 131-byte keys).  Keys shorter than KEY_BYTES are zero-padded, which is
# what HMAC's own padding to 64 bytes does anyway.
RFC4231 = [
    (bytes([0x0b] * 20), b'Hi There',
     'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
    (b'Jefe', b'what do ya want for nothing?',
     '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
    (bytes([0xaa] * 20), bytes([0xdd] * 50),
     '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'),
    (bytes(range(1, 26)), bytes([0xcd] * 50),
     '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'),
]


def pack(data, width):
    '''Byte 0 in the top bits of a width-byte bus.'''
    assert len(data) <= width
    return int.from_bytes(data.ljust(width, b'\0'), 'big')


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    dut.start.value = 0
    dut.key.value = 0
    dut.msg.value = 0
    dut.msg_len.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)


async def run_hmac(dut, key, msg, limit=10000):
    '''Start one HMAC; return (mac bytes, cycles from start to done).'''
    assert dut.ready.value == 1
    dut.key.value = pack(key, KEY_BYTES)
    dut.msg.value = pack(msg, MAX_MSG_BYTES)
    dut.msg_len.value = len(msg)
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    for cycles in range(1, limit):
        await RisingEdge(dut.clk)
        await Timer(1, units='ns')
        assert dut.err.value == 0
        if dut.done.value:
            return int(dut.mac.value).to_bytes(32, 'big'), cycles
    raise AssertionError(f'no done after {limit} cycles')


@cocotb.test(skip=GateLevelTest)
async def test_rfc4231(dut):
    await setup(dut)
    for n, (key, msg, expected) in enumerate(RFC4231, 1):
        mac, cycles = await run_hmac(dut, key, msg)
        dut._log.info(f'RFC 4231 case {n}: {mac.hex()} ({cycles} cycles)')
        assert mac.hex() == expected
        assert mac == hmac.new(key, msg, hashlib.sha256).digest()
        await ClockCycles(dut.clk, 3)


@cocotb.test(skip=GateLevelTest)
async def test_random_back_to_back(dut):
    '''Random keys and messages of every length 0..55, back to back.'''
    await setup(dut)
    rng = random.Random(4231)
    counts = set()
    for length in range(MAX_MSG_BYTES + 1):
        key = bytes(rng.randrange(256) for _ in range(rng.randint(1, KEY_BYTES)))
        msg = bytes(rng.randrange(256) for _ in range(length))
        mac, cycles = await run_hmac(dut, key, msg)
        assert mac == hmac.new(key, msg, hashlib.sha256).digest(), f'len {length}'
        counts.add(cycles)
        await RisingEdge(dut.clk)
    dut._log.info(f'all {MAX_MSG_BYTES + 1} lengths correct; start-to-done cycles: '
                  f'{min(counts)}-{max(counts)}')


@cocotb.test(skip=GateLevelTest)
async def test_length_error(dut):
    await setup(dut)
    dut.msg_len.value = MAX_MSG_BYTES + 1
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await Timer(1, units='ns')  # err is a one-cycle pulse after the start edge
    assert dut.err.value == 1
    assert dut.ready.value == 1
    await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    assert dut.err.value == 0
    mac, _ = await run_hmac(dut, b'k', b'still works')
    assert mac == hmac.new(b'k', b'still works', hashlib.sha256).digest()


def ctrl_registers(dut):
    regs = {}
    for name in ('inner', 'mac', 'len', 'idx', 'rd_idx', 'state',
                 'outer', 'core_data'):
        regs[name] = getattr(dut.ctrl, name).value.binstr
    return regs


@cocotb.test(skip=GateLevelTest)
async def test_key_not_stored(dut):
    '''No controller register ever holds 4 consecutive key bytes.'''
    await setup(dut)
    key = bytes(range(0xa0, 0xa0 + KEY_BYTES))
    windows = {key[i:i + 4] for i in range(len(key) - 3)}
    windows |= {bytes(b ^ p for b in w) for w in windows for p in (0x36, 0x5c)}
    dut.key.value = pack(key, KEY_BYTES)
    dut.msg.value = pack(b'x', MAX_MSG_BYTES)
    dut.msg_len.value = 1
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    while not dut.done.value:
        await RisingEdge(dut.clk)
        await Timer(1, units='ns')
        for name, bits in ctrl_registers(dut).items():
            if len(bits) % 8:
                continue
            raw = int(bits, 2).to_bytes(len(bits) // 8, 'big')
            hit = [w for w in windows if w in raw]
            assert not hit, f'key material found in ctrl.{name}'


@cocotb.test(skip=GateLevelTest)
async def test_reset_mid_outer_zeroizes(dut):
    '''One-cycle reset while the inner digest is held: every register in the
    controller and the core reads zero, and the next HMAC is correct.'''
    await setup(dut)
    key, msg = b'zeroize me' * 3, b'nonce=1234'
    dut.key.value = pack(key, KEY_BYTES)
    dut.msg.value = pack(msg, MAX_MSG_BYTES)
    dut.msg_len.value = len(msg)
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    # wait until the outer hash is streaming its key block
    while not (dut.ctrl.outer.value == 1 and int(dut.ctrl.idx.value) == 20):
        await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    assert '1' in dut.ctrl.inner.value.binstr, 'inner digest should be held here'

    dut.rst_n.value = 0
    await RisingEdge(dut.clk)
    dut.rst_n.value = 1
    await Timer(1, units='ns')

    ctrl = {k: v for k, v in ctrl_registers(dut).items()}
    nonzero = [k for k, v in ctrl.items() if v.strip('0')]
    assert not nonzero, f'controller registers not cleared: {nonzero}'
    core = snapshot(dut.core)
    regs = all_registers()
    nonzero = [r for r in regs if core[r].strip('0')]
    assert not nonzero, f'core registers not cleared: {nonzero}'
    dut._log.info(f'controller and all {len(regs)} core registers zero after a 1-cycle reset')

    await ClockCycles(dut.clk, 5)
    mac, _ = await run_hmac(dut, key, msg)
    assert mac == hmac.new(key, msg, hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_inner_digest_wiped_after_use(dut):
    '''The inner digest register is all zero once the outer hash has consumed it.'''
    await setup(dut)
    key, msg = b'k' * 32, b'm'
    dut.key.value = pack(key, KEY_BYTES)
    dut.msg.value = pack(msg, MAX_MSG_BYTES)
    dut.msg_len.value = len(msg)
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    while not (dut.ctrl.outer.value == 1 and int(dut.ctrl.idx.value) == 96):
        await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    assert not dut.ctrl.inner.value.binstr.strip('0'), 'inner digest still present'
    while not dut.done.value:
        await RisingEdge(dut.clk)
        await Timer(1, units='ns')
    assert not dut.ctrl.inner.value.binstr.strip('0')
