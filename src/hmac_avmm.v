/*
 * hmac_avmm: Avalon-MM slave around hmac_ctrl and the shaman core, for the
 * DE10-Nano HPS (Linux on the ARM, via the lightweight HPS-to-FPGA bridge).
 *
 * One clock domain.  32-bit registers, word addressing, read latency 1, no
 * wait states.  Byte order is little-endian within each word, so a byte
 * buffer on the ARM can be copied word by word: register word i, bits [7:0],
 * holds byte 4*i.
 *
 *   byte offset  name        access  contents
 *   0x00         CTRL        W       bit0 START, bit1 CLEAR_KEY, bit2 CLEAR_DATA
 *   0x04         STATUS      R       bit0 READY, bit1 DONE, bit2 ERR, bit3 KEY_LOADED,
 *                                    bit4 TAMPERED
 *   0x08         MSG_LEN     R/W     message length in bytes, 0..55
 *   0x0C         ID          R       0x484D4143 ("HMAC")
 *   0x20..0x3C   KEY[0..7]   W       32-byte key; reads return 0
 *   0x40..0x74   MSG[0..13]  W       message bytes 0..55 (byte 55 is ignored)
 *   0x80..0x9C   MAC[0..7]   R       HMAC-SHA256 of the last operation
 *
 * Key policy: the key is kept for any number of operations until CLEAR_KEY,
 * tamper or reset; it is write-only over the bus.  Any software that can
 * reach the bridge can still use it, so access must be restricted on the
 * Linux side.
 *
 * START is accepted only when READY and KEY_LOADED; otherwise, or when
 * MSG_LEN > 55, ERR is set and nothing runs.  DONE and ERR are cleared by the
 * next accepted START or by a CLEAR.  KEY/MSG/MSG_LEN writes are ignored while
 * an operation runs.
 *
 * Constant time: DONE is raised exactly LATENCY cycles after the clock edge
 * that accepts START, whatever the key or message.  READY stays low and MAC
 * reads return 0 until then, so nothing on the bus reveals when the core
 * actually finished.  (If the core were ever later than LATENCY, DONE would
 * wait for it and lat_overrun would be set; the tests check it never is.)
 *
 * Tamper: tamper_n (active-low push-button) is synchronised by two flip-flops.
 * The synchronised signal clears the KEY registers asynchronously, holds
 * hmac_ctrl in reset and the core in reset (the core's reset is synchronous,
 * so it takes effect on the next clock edge), and otherwise acts exactly like
 * CLEAR_KEY.  From the first clock edge that samples tamper_n low, all state
 * is cleared within 3 cycles.  STATUS.TAMPERED stays set until reset.
 *
 * Illegal FSM states: the operation FSM's default branch performs the
 * CLEAR_KEY action (the register is marked syn_encoding "safe" so synthesis
 * keeps the recovery logic).
 *
 * Zeroization:
 *   - after every operation the core is reset for 2 cycles, so no inner
 *     digest or message schedule is left in it;
 *   - CLEAR_KEY, tamper and an illegal FSM state clear the key and the MAC and
 *     abort any running operation; CLEAR_DATA clears MSG, MSG_LEN and the MAC
 *     and aborts.  An abort resets hmac_ctrl and the core for 2 cycles;
 *   - reset clears everything.
 */

`default_nettype none

module hmac_avmm (
    input  wire        clk,
    input  wire        reset,            // active high, Avalon convention
    input  wire        tamper_n,         // active-low tamper push-button, asynchronous

    input  wire [5:0]  avs_address,      // word address
    input  wire        avs_read,
    output reg  [31:0] avs_readdata,
    input  wire        avs_write,
    input  wire [31:0] avs_writedata
);

  localparam [31:0] ID_VALUE = 32'h484D4143;

  // START-accept edge to DONE, in cycles.  hmac_ctrl needs 2652..2656 cycles
  // from its start pulse, plus 1 cycle for the pulse and 2 for the core scrub.
  localparam [11:0] LATENCY = 12'd2688;

  localparam A_CTRL    = 6'h00,
             A_STATUS  = 6'h01,
             A_MSG_LEN = 6'h02,
             A_ID      = 6'h03,
             A_KEY     = 6'h08,   // ..0x0F
             A_MSG     = 6'h10,   // ..0x1D
             A_MAC     = 6'h20;   // ..0x27

  localparam [1:0] P_IDLE = 2'd0,
                   P_RUN  = 2'd1;  // 2'd2, 2'd3 are illegal

  // ---- registers -----------------------------------------------------------
  reg [31:0] key_w [0:7];
  reg [31:0] msg_w [0:13];
  reg [5:0]  msg_len;
  reg        key_loaded;
  reg        done_flag;
  reg        err_flag;
  reg        tampered;
  reg        start_pulse;
  (* syn_encoding = "safe" *) reg [1:0] phase;
  reg [11:0] cnt;           // cycles since START was accepted
  reg        ctrl_finished; // hmac_ctrl has signalled done for this operation
  reg        lat_overrun;   // debug: hmac_ctrl later than LATENCY (never expected)
  reg        tamper_ff1, tamper_ff2;
  // 2-cycle reset pulses as shift registers (11 -> 10 -> 00): one bit changes
  // per transition, so the OR that drives hmac_ctrl's asynchronous reset
  // cannot glitch when it is released.
  reg [1:0]  abort_sr;      // hmac_ctrl + core reset after a CLEAR
  reg [1:0]  scrub_sr;      // core-only reset after each operation

  wire       ctrl_ready, ctrl_done, ctrl_err;
  wire [255:0] ctrl_mac;

  wire tamper    = tamper_ff2;
  wire aborting  = |abort_sr;
  wire scrubbing = |scrub_sr;
  wire ready     = phase == P_IDLE && ctrl_ready && !aborting && !scrubbing &&
                   !start_pulse && !tamper;

  // tamper is a flip-flop output, so it is safe to use in these resets
  wire ctrl_rst_n = !reset && !aborting && !tamper;
  wire core_rst_n = !reset && !aborting && !scrubbing && !tamper;

  wire wr_ctrl       = avs_write && avs_address == A_CTRL;
  wire do_start      = wr_ctrl && avs_writedata[0];
  wire do_clear_data = wr_ctrl && avs_writedata[2];
  wire illegal_phase = phase != P_IDLE && phase != P_RUN;
  // the CLEAR_KEY action: bus request, tamper or illegal FSM state
  wire clear_key     = (wr_ctrl && avs_writedata[1]) || tamper || illegal_phase;
  wire do_clear      = clear_key || do_clear_data;

  integer i;

  // ---- tamper synchroniser -------------------------------------------------
  always @(posedge clk) begin
    if (reset) begin
      tamper_ff1 <= 1'b0;
      tamper_ff2 <= 1'b0;
    end else begin
      tamper_ff1 <= !tamper_n;
      tamper_ff2 <= tamper_ff1;
    end
  end

  // ---- key registers: cleared asynchronously by the synchronised tamper ----
  always @(posedge clk or posedge tamper) begin
    if (tamper) begin
      for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
      key_loaded <= 1'b0;
    end else if (reset || clear_key) begin
      for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
      key_loaded <= 1'b0;
    end else if (avs_write && ready && avs_address >= A_KEY && avs_address < A_KEY + 6'd8) begin
      key_w[avs_address - A_KEY] <= avs_writedata;
      key_loaded <= 1'b1;
    end
  end

  // ---- control ---------------------------------------------------------------
  always @(posedge clk) begin
    if (reset) begin
      for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
      msg_len       <= 6'd0;
      done_flag     <= 1'b0;
      err_flag      <= 1'b0;
      tampered      <= 1'b0;
      start_pulse   <= 1'b0;
      phase         <= P_IDLE;
      cnt           <= 12'd0;
      ctrl_finished <= 1'b0;
      lat_overrun   <= 1'b0;
      abort_sr      <= 2'b00;
      scrub_sr      <= 2'b00;
    end else begin
      start_pulse <= 1'b0;
      abort_sr    <= {abort_sr[0], 1'b0};
      scrub_sr    <= {scrub_sr[0], 1'b0};
      if (tamper) tampered <= 1'b1;

      if (do_clear) begin
        abort_sr      <= 2'b11;
        scrub_sr      <= 2'b00;
        phase         <= P_IDLE;
        cnt           <= 12'd0;
        ctrl_finished <= 1'b0;
        done_flag     <= 1'b0;
        err_flag      <= 1'b0;
        if (do_clear_data) begin
          for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
          msg_len <= 6'd0;
        end
      end else begin
        case (phase)
          P_IDLE: begin
            if (do_start) begin
              if (ready && key_loaded && msg_len <= 6'd55) begin
                start_pulse   <= 1'b1;
                done_flag     <= 1'b0;
                err_flag      <= 1'b0;
                cnt           <= 12'd1;
                ctrl_finished <= 1'b0;
                phase         <= P_RUN;
              end else begin
                err_flag <= 1'b1;
              end
            end else if (avs_write && ready) begin
              if (avs_address == A_MSG_LEN)
                msg_len <= avs_writedata[5:0];
              if (avs_address >= A_MSG && avs_address < A_MSG + 6'd14)
                msg_w[avs_address - A_MSG] <= avs_writedata;
            end
          end

          P_RUN: begin
            if (do_start)
              err_flag <= 1'b1;            // START while busy is refused
            if (ctrl_done) begin
              ctrl_finished <= 1'b1;
              scrub_sr      <= 2'b11;
            end
            if (ctrl_err)
              err_flag <= 1'b1;
            if (cnt != LATENCY)
              cnt <= cnt + 12'd1;
            if (cnt == LATENCY) begin
              if (ctrl_finished && !scrubbing) begin
                done_flag <= 1'b1;
                phase     <= P_IDLE;
              end else begin
                lat_overrun <= 1'b1;
              end
            end
          end

          default: ;  // illegal: clear_key is already asserted (illegal_phase)
        endcase
      end
    end
  end

  // ---- read path (latency 1) ----------------------------------------------
  wire [255:0] mac_le;      // MAC byte 4*i in mac word i bits [7:0]
  genvar g;
  generate
    for (g = 0; g < 32; g = g + 1) begin : g_mac
      assign mac_le[8*g +: 8] = ctrl_mac[255 - 8*g -: 8];
    end
  endgenerate

  always @(posedge clk) begin
    if (reset) begin
      avs_readdata <= 32'd0;
    end else if (avs_read) begin
      avs_readdata <= 32'd0;
      if (avs_address == A_STATUS)
        avs_readdata <= {27'd0, tampered, key_loaded, err_flag, done_flag, ready};
      else if (avs_address == A_MSG_LEN)
        avs_readdata <= {26'd0, msg_len};
      else if (avs_address == A_ID)
        avs_readdata <= ID_VALUE;
      else if (avs_address >= A_MAC && avs_address < A_MAC + 6'd8 && done_flag)
        avs_readdata <= mac_le[32*(avs_address - A_MAC) +: 32];
    end
  end

  // ---- byte-order conversion to hmac_ctrl (byte 0 in the top bits) --------
  wire [255:0] key_be;
  wire [439:0] msg_be;
  generate
    for (g = 0; g < 32; g = g + 1) begin : g_key
      assign key_be[255 - 8*g -: 8] = key_w[g / 4][8*(g % 4) +: 8];
    end
    for (g = 0; g < 55; g = g + 1) begin : g_msg
      assign msg_be[439 - 8*g -: 8] = msg_w[g / 4][8*(g % 4) +: 8];
    end
  endgenerate

  // ---- datapath --------------------------------------------------------------
  wire [7:0] core_data;
  wire       core_clockin, core_start, core_parallel, core_result_next;
  wire [7:0] core_uo_out, core_uio_out, core_uio_oe;

  hmac_ctrl #(
      .KEY_BYTES(32),
      .MAX_MSG_BYTES(55)
  ) ctrl (
      .clk              (clk),
      .rst_n            (ctrl_rst_n),
      .key              (key_be),
      .msg              (msg_be),
      .msg_len          (msg_len),
      .start            (start_pulse),
      .ready            (ctrl_ready),
      .done             (ctrl_done),
      .err              (ctrl_err),
      .mac              (ctrl_mac),
      .core_data        (core_data),
      .core_clockin     (core_clockin),
      .core_start       (core_start),
      .core_parallel    (core_parallel),
      .core_result_next (core_result_next),
      .core_busy        (core_uio_out[4]),
      .core_result_ready(core_uio_out[0]),
      .core_result_byte (core_uo_out)
  );

  tt_um_psychogenic_shaman core (
      .ui_in  (core_data),
      .uo_out (core_uo_out),
      .uio_in ({core_clockin, core_start, 2'b00, core_result_next, core_parallel, 2'b00}),
      .uio_out(core_uio_out),
      .uio_oe (core_uio_oe),
      .ena    (1'b1),
      .clk    (clk),
      .rst_n  (core_rst_n)
  );

endmodule
