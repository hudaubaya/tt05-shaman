# Platform Designer system with both HMAC slaves at different addresses:
#
#   hmac_tt05  (tt05-shaman hmac_avmm)        base 0x0000, span 0x100
#   hmac_tt07  (tt07-sha256 hmac07_avmm)      base 0x1000, span 0x100
#
# An Avalon-MM bridge (exported as hmac_s0) fronts both slaves; connect it to
# the HPS h2f_lw_axi_master in the DE10-Nano GHRD, so the slaves appear at
# 0xFF200000 + <bridge base> + 0x0000 / 0x1000.  Each slave's tamper input is
# exported separately (tamper_tt05, tamper_tt07); tie both to the same
# push-button if wanted.
#
# Generate with:  qsys-script --script=hmac_dual_system.tcl
#                 (with both repositories' fpga/ directories on the IP search path)
#
# Requirements (met in both repositories):
#   - the tt07 modules and component are named hmac07_avmm / hmac07_ctrl, so
#     they do not clash with tt05's hmac_avmm / hmac_ctrl;
#   - both hw.tcl files export tamper_n as a conduit interface named "tamper".
# The combined RTL compiles and has been simulated behind an equivalent
# address decoder; this script itself has not been run in Platform Designer.

package require -exact qsys 16.1

create_system hmac_dual
set_project_property DEVICE_FAMILY {Cyclone V}
set_project_property DEVICE {5CSEBA6U23I7}

# clock and reset
add_instance clk_0 clock_source
set_instance_parameter_value clk_0 clockFrequency {50000000.0}
set_instance_parameter_value clk_0 clockFrequencyKnown {1}
set_instance_parameter_value clk_0 resetSynchronousEdges {DEASSERT}

# bridge in front of both slaves (connect hmac_s0 to the HPS lightweight bridge)
add_instance mm_bridge_0 altera_avalon_mm_bridge
set_instance_parameter_value mm_bridge_0 DATA_WIDTH {32}
set_instance_parameter_value mm_bridge_0 ADDRESS_WIDTH {13}
set_instance_parameter_value mm_bridge_0 ADDRESS_UNITS {SYMBOLS}
set_instance_parameter_value mm_bridge_0 MAX_BURST_SIZE {1}

# the two HMAC slaves
add_instance hmac_tt05 hmac_avmm
add_instance hmac_tt07 hmac07_avmm

# clocks
add_connection clk_0.clk mm_bridge_0.clk
add_connection clk_0.clk hmac_tt05.clock
add_connection clk_0.clk hmac_tt07.clock

# resets
add_connection clk_0.clk_reset mm_bridge_0.reset
add_connection clk_0.clk_reset hmac_tt05.reset
add_connection clk_0.clk_reset hmac_tt07.reset

# address map
add_connection mm_bridge_0.m0 hmac_tt05.s0
set_connection_parameter_value mm_bridge_0.m0/hmac_tt05.s0 baseAddress {0x0000}
add_connection mm_bridge_0.m0 hmac_tt07.s0
set_connection_parameter_value mm_bridge_0.m0/hmac_tt07.s0 baseAddress {0x1000}

# exports
add_interface clk clock sink
set_interface_property clk EXPORT_OF clk_0.clk_in
add_interface reset reset sink
set_interface_property reset EXPORT_OF clk_0.clk_in_reset
add_interface hmac_s0 avalon slave
set_interface_property hmac_s0 EXPORT_OF mm_bridge_0.s0
add_interface tamper_tt05 conduit end
set_interface_property tamper_tt05 EXPORT_OF hmac_tt05.tamper
add_interface tamper_tt07 conduit end
set_interface_property tamper_tt07 EXPORT_OF hmac_tt07.tamper

save_system hmac_dual.qsys
