`default_nettype none
// Simulation stand-in for hmac_dual_system: byte address bit 12 selects the
// slave (tt05 at 0x0000, tt07 at 0x1000), word address = addr[7:2].
module dual_top (
    input  wire        clk, reset,
    input  wire        tamper_tt05_n, tamper_tt07_n,
    input  wire [12:0] address,
    input  wire        read, write,
    input  wire [31:0] writedata,
    output wire [31:0] readdata
);
  wire sel07 = address[12];
  reg  sel07_q;
  always @(posedge clk) if (read) sel07_q <= sel07;
  wire [31:0] rd05, rd07;
  assign readdata = sel07_q ? rd07 : rd05;
  hmac_avmm   hmac_tt05 (.clk(clk), .reset(reset), .tamper_n(tamper_tt05_n),
      .avs_address(address[7:2]), .avs_read(read && !sel07), .avs_readdata(rd05),
      .avs_write(write && !sel07), .avs_writedata(writedata));
  hmac07_avmm hmac_tt07 (.clk(clk), .reset(reset), .tamper_n(tamper_tt07_n),
      .avs_address(address[7:2]), .avs_read(read && sel07), .avs_readdata(rd07),
      .avs_write(write && sel07), .avs_writedata(writedata));
endmodule
