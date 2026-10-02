'''
Tests for hmac_avmm.v (Avalon-MM wrapper: hmac_ctrl + shaman core).

Run with:  make AVMM=yes
'''

import hashlib
import hmac
import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

from test_hmac import all_registers
from test_hmac_ctrl import RFC4231
from test_zeroize import snapshot

GateLevelTest = os.environ.get('GATES') == 'yes'

CLK_PERIOD_NS = 20

CTRL, STATUS, MSG_LEN, ID = 0x00, 0x04, 0x08, 0x0C
KEY, MSG, MAC = 0x20, 0x40, 0x80
START, CLEAR_KEY, CLEAR_DATA = 1, 2, 4
READY, DONE, ERR, KEY_LOADED = 1, 2, 4, 8


class Bus:
    '''Minimal Avalon-MM master: one transfer per call, read latency 1.'''

    def __init__(self, dut):
        self.dut = dut
        self.transfers = 0

    async def write(self, offset, value):
        d = self.dut
        d.avs_address.value = offset >> 2
        d.avs_writedata.value = value
        d.avs_write.value = 1
        await RisingEdge(d.clk)
        d.avs_write.value = 0
        self.transfers += 1

    async def read(self, offset):
        d = self.dut
        d.avs_address.value = offset >> 2
        d.avs_read.value = 1
        await RisingEdge(d.clk)
        d.avs_read.value = 0
        await Timer(1, units='ns')
        self.transfers += 1
        return int(d.avs_readdata.value)

    async def write_bytes(self, offset, data, words):
        data = data.ljust(4 * words, b'\0')
        for i in range(words):
            await self.write(offset + 4 * i, int.from_bytes(data[4 * i:4 * i + 4], 'little'))

    async def read_bytes(self, offset, words):
        out = b''
        for i in range(words):
            out += (await self.read(offset + 4 * i)).to_bytes(4, 'little')
        return out


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    dut.avs_read.value = 0
    dut.avs_write.value = 0
    dut.avs_address.value = 0
    dut.avs_writedata.value = 0
    dut.reset.value = 1
    await ClockCycles(dut.clk, 5)
    dut.reset.value = 0
    await ClockCycles(dut.clk, 10)
    await Timer(1, units='ns')
    bus = Bus(dut)
    bus.clean_core = snapshot(dut.core)   # idle core after a clean reset
    return bus


def core_residue(bus):
    '''Core flip-flops that differ from an idle core after a clean reset.
    (A few control registers, e.g. bp_procst, idle at 1, not 0.)'''
    core = snapshot(bus.dut.core)
    return [r for r in all_registers() if core[r] != bus.clean_core[r]]


async def wait_status(bus, mask, limit=10000):
    for _ in range(limit):
        st = await bus.read(STATUS)
        if st & mask == mask:
            return st
    raise AssertionError(f'status {mask:#x} not reached')


async def mac_of(bus, msg, key=None):
    if key is not None:
        await bus.write_bytes(KEY, key, 8)
    await bus.write_bytes(MSG, msg, 14)
    await bus.write(MSG_LEN, len(msg))
    await bus.write(CTRL, START)
    st = await wait_status(bus, DONE)
    assert not st & ERR
    return await bus.read_bytes(MAC, 8)


@cocotb.test(skip=GateLevelTest)
async def test_id_and_rfc4231(dut):
    bus = await setup(dut)
    assert await bus.read(ID) == 0x484D4143
    assert await bus.read(STATUS) == READY
    for n, (key, msg, expected) in enumerate(RFC4231, 1):
        mac = await mac_of(bus, msg, key)
        dut._log.info(f'RFC 4231 case {n} over Avalon-MM: {mac.hex()}')
        assert mac.hex() == expected


@cocotb.test(skip=GateLevelTest)
async def test_key_reuse(dut):
    '''Key written once, 20 messages of random length, all correct.'''
    bus = await setup(dut)
    rng = random.Random(10)
    key = bytes(rng.randrange(256) for _ in range(32))
    await bus.write_bytes(KEY, key, 8)
    for _ in range(20):
        msg = bytes(rng.randrange(256) for _ in range(rng.randint(0, 55)))
        assert await mac_of(bus, msg) == hmac.new(key, msg, hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_key_write_only(dut):
    bus = await setup(dut)
    await bus.write_bytes(KEY, bytes(range(1, 33)), 8)
    for i in range(8):
        assert await bus.read(KEY + 4 * i) == 0, 'key readable over the bus'
    assert await bus.read(STATUS) & KEY_LOADED


@cocotb.test(skip=GateLevelTest)
async def test_errors(dut):
    bus = await setup(dut)
    # START without a key
    await bus.write(CTRL, START)
    st = await bus.read(STATUS)
    assert st & ERR and st & READY and not st & KEY_LOADED
    # message too long
    await bus.write_bytes(KEY, b'k' * 32, 8)
    await bus.write(MSG_LEN, 56)
    await bus.write(CTRL, START)
    assert await bus.read(STATUS) & ERR
    # START while busy is refused, writes while busy are ignored
    await bus.write(MSG_LEN, 3)
    await bus.write_bytes(MSG, b'abc', 14)
    await bus.write(CTRL, START)
    assert not (await bus.read(STATUS)) & ERR
    await bus.write(CTRL, START)
    assert (await bus.read(STATUS)) & ERR
    await bus.write(MSG_LEN, 9)
    assert await bus.read(MSG_LEN) == 3
    # the running operation still completes correctly
    await wait_status(bus, DONE)
    mac = await bus.read_bytes(MAC, 8)
    assert mac == hmac.new(b'k' * 32, b'abc', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_core_scrubbed_after_each_operation(dut):
    '''After DONE the core holds nothing: all 61 flip-flops match an idle core
    after a clean reset, and the controller's inner digest is zero.'''
    bus = await setup(dut)
    await mac_of(bus, b'scrub test message', b'K' * 32)
    await wait_status(bus, READY)
    await ClockCycles(dut.clk, 5)
    await Timer(1, units='ns')
    residue = core_residue(bus)
    assert not residue, f'core state left after operation: {residue}'
    assert not dut.ctrl.inner.value.binstr.strip('0')


@cocotb.test(skip=GateLevelTest)
async def test_clear_key_and_abort(dut):
    '''CLEAR_KEY mid-operation aborts, zeroizes key, MAC, controller and core.'''
    bus = await setup(dut)
    key = b'abort-me' * 4
    await mac_of(bus, b'first', key)
    await bus.write(CTRL, START)                 # same key and message again
    await ClockCycles(dut.clk, 900)              # well into the inner hash
    assert not (await bus.read(STATUS)) & READY
    await bus.write(CTRL, CLEAR_KEY)
    await ClockCycles(dut.clk, 3)
    await Timer(1, units='ns')

    for i in range(8):
        assert not dut.key_w[i].value.binstr.strip('0'), f'key word {i} not cleared'
    assert await bus.read_bytes(MAC, 8) == bytes(32)
    for name in ('inner', 'mac', 'state', 'idx'):
        assert not getattr(dut.ctrl, name).value.binstr.strip('0'), f'ctrl.{name}'
    await ClockCycles(dut.clk, 5)
    await Timer(1, units='ns')
    residue = core_residue(bus)
    assert not residue, f'core not cleared: {residue}'
    st = await bus.read(STATUS)
    assert st & READY and not st & KEY_LOADED and not st & DONE

    await bus.write(CTRL, START)                 # refused: no key
    assert (await bus.read(STATUS)) & ERR
    assert await mac_of(bus, b'first', key) == hmac.new(key, b'first', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_clear_data(dut):
    bus = await setup(dut)
    key = b'keep this key!!!' * 2
    await mac_of(bus, b'some data', key)
    await bus.write(CTRL, CLEAR_DATA)
    await ClockCycles(dut.clk, 3)
    for i in range(14):
        assert not dut.msg_w[i].value.binstr.strip('0')
    assert await bus.read(MSG_LEN) == 0
    assert await bus.read_bytes(MAC, 8) == bytes(32)
    st = await bus.read(STATUS)
    assert st & KEY_LOADED, 'CLEAR_DATA must keep the key'
    assert await mac_of(bus, b'next') == hmac.new(key, b'next', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_bus_level_latency(dut):
    '''Cycles and bus transfers for one HMAC, key already loaded.'''
    bus = await setup(dut)
    key = bytes(32)
    await bus.write_bytes(KEY, key, 8)
    msg = b'authenticate me: nonce=8f3a21c0'
    count = {'n': 0}

    async def counter():
        while True:
            await RisingEdge(dut.clk)
            count['n'] += 1
    cocotb.start_soon(counter())
    t0, x0 = count['n'], bus.transfers
    mac = await mac_of(bus, msg)
    total, transfers = count['n'] - t0, bus.transfers - x0
    assert mac == hmac.new(key, msg, hashlib.sha256).digest()
    dut._log.info(f'one HMAC over the bus (key loaded): {total} cycles, '
                  f'{transfers} transfers incl. STATUS polling')
