# Both HMAC wrappers behind one address decoder (see fpga/hmac_dual_system.tcl).
import hashlib, hmac
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

async def wr(d, a, v):
    d.address.value = a; d.writedata.value = v; d.write.value = 1
    await RisingEdge(d.clk); d.write.value = 0

async def rd(d, a):
    d.address.value = a; d.read.value = 1
    await RisingEdge(d.clk); d.read.value = 0
    await Timer(1, units='ns'); return int(d.readdata.value)

async def mac(d, base, key, msg):
    key = key.ljust(32, b'\0'); m = msg.ljust(56, b'\0')
    for i in range(8):  await wr(d, base + 0x20 + 4*i, int.from_bytes(key[4*i:4*i+4], 'little'))
    for i in range(14): await wr(d, base + 0x40 + 4*i, int.from_bytes(m[4*i:4*i+4], 'little'))
    await wr(d, base + 0x08, len(msg)); await wr(d, base + 0x00, 1)
    while not (await rd(d, base + 0x04)) & 2: pass
    out = b''
    for i in range(8):
        out += (await rd(d, base + 0x80 + 4*i)).to_bytes(4, 'little')
    return out

@cocotb.test()
async def test_both_slaves(dut):
    cocotb.start_soon(Clock(dut.clk, 20, units='ns').start())
    dut.read.value = dut.write.value = 0; dut.address.value = 0; dut.writedata.value = 0
    dut.tamper_tt05_n.value = 1; dut.tamper_tt07_n.value = 1
    dut.reset.value = 1; await ClockCycles(dut.clk, 5); dut.reset.value = 0; await ClockCycles(dut.clk, 3)
    assert await rd(dut, 0x000C) == 0x484D4143 and await rd(dut, 0x100C) == 0x484D4143
    exp = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
    for base in (0x0000, 0x1000):
        m = await mac(dut, base, b'Jefe', b'what do ya want for nothing?')
        dut._log.info(f'slave @0x{base:04x}: {m.hex()}'); assert m.hex() == exp
    # tamper only tt07: tt07 loses its key, tt05 keeps it
    dut.tamper_tt07_n.value = 0; await ClockCycles(dut.clk, 4); dut.tamper_tt07_n.value = 1; await ClockCycles(dut.clk, 4)
    s05, s07 = await rd(dut, 0x0004), await rd(dut, 0x1004)
    dut._log.info(f'after tamper_tt07: STATUS tt05={s05:#x} tt07={s07:#x}')
    assert s05 & 8 and not s05 & 16, 'tt05 must be unaffected'
    assert not s07 & 8 and s07 & 16, 'tt07 must be cleared and TAMPERED'
    m = await mac(dut, 0x0000, b'Jefe', b'what do ya want for nothing?'); assert m.hex() == exp
