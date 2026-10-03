# Simulates both HMAC wrappers behind an address decoder equivalent to
# fpga/hmac_dual_system.tcl (tt05 at 0x0000, tt07 at 0x1000).
# Needs a checkout of tt07-sha256 next to tt05-shaman, or set TT07=<path>.
#   make            (from this directory)

SIM ?= icarus
TOPLEVEL_LANG ?= verilog
TT05 = $(abspath $(PWD)/../../src)
TT07 ?= $(abspath $(PWD)/../../../tt07-sha256/src)

VERILOG_SOURCES = $(PWD)/dual_top.v \
                  $(TT05)/hmac_avmm.v $(TT05)/hmac_ctrl.v $(TT05)/tt_um_psychogenic_shaman.v \
                  $(TT07)/hmac07_avmm.v $(TT07)/hmac07_ctrl.v $(TT07)/sha07_block.v $(TT07)/project.v
TOPLEVEL = dual_top
MODULE = test_dual

include $(shell cocotb-config --makefiles)/Makefile.sim
