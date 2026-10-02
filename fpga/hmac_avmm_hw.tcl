# Platform Designer (Qsys) component for hmac_avmm.
#
# Put this file in a directory on the Platform Designer IP search path (or
# the project directory), add "HMAC-SHA256 (shaman)" to the system, and
# connect s0 to the HPS h2f_lw_axi_master.  Clock and reset must come from the
# same clock domain as the bridge side you connect.
#
# Not yet opened in Quartus/Platform Designer: check the component editor for
# warnings on first use.

package require -exact qsys 16.1

set_module_property NAME hmac_avmm
set_module_property DISPLAY_NAME "HMAC-SHA256 (shaman)"
set_module_property VERSION 1.0
set_module_property GROUP "Cryptography"
set_module_property DESCRIPTION "HMAC-SHA256 on the shaman SHA256 core, Avalon-MM slave"
set_module_property EDITABLE false

add_fileset QUARTUS_SYNTH QUARTUS_SYNTH "" ""
set_fileset_property QUARTUS_SYNTH TOP_LEVEL hmac_avmm
add_fileset_file hmac_avmm.v VERILOG PATH ../src/hmac_avmm.v TOP_LEVEL_FILE
add_fileset_file hmac_ctrl.v VERILOG PATH ../src/hmac_ctrl.v
add_fileset_file tt_um_psychogenic_shaman.v VERILOG PATH ../src/tt_um_psychogenic_shaman.v

add_fileset SIM_VERILOG SIM_VERILOG "" ""
set_fileset_property SIM_VERILOG TOP_LEVEL hmac_avmm
add_fileset_file hmac_avmm.v VERILOG PATH ../src/hmac_avmm.v
add_fileset_file hmac_ctrl.v VERILOG PATH ../src/hmac_ctrl.v
add_fileset_file tt_um_psychogenic_shaman.v VERILOG PATH ../src/tt_um_psychogenic_shaman.v

# clock
add_interface clock clock end
set_interface_property clock clockRate 0
add_interface_port clock clk clk Input 1

# reset (active high, synchronous deassertion from the reset controller)
add_interface reset reset end
set_interface_property reset associatedClock clock
set_interface_property reset synchronousEdges DEASSERT
add_interface_port reset reset reset Input 1

# Avalon-MM slave: 64 words x 32 bit, read latency 1, no wait states
add_interface s0 avalon end
set_interface_property s0 addressUnits WORDS
set_interface_property s0 associatedClock clock
set_interface_property s0 associatedReset reset
set_interface_property s0 bitsPerSymbol 8
set_interface_property s0 maximumPendingReadTransactions 0
set_interface_property s0 readLatency 1
set_interface_property s0 readWaitTime 0
set_interface_property s0 writeWaitTime 0
set_interface_property s0 setupTime 0
set_interface_property s0 holdTime 0
add_interface_port s0 avs_address address Input 6
add_interface_port s0 avs_read read Input 1
add_interface_port s0 avs_readdata readdata Output 32
add_interface_port s0 avs_write write Input 1
add_interface_port s0 avs_writedata writedata Input 32
