/*
 * hmac_ctrl: drives the shaman SHA256 core to compute HMAC-SHA256.
 *
 *   inner = SHA256((K ^ ipad) || msg)
 *   mac   = SHA256((K ^ opad) || inner)
 *
 * Each hash is exactly two 64-byte blocks: the padded key block and one
 * message block, so msg_len is limited to MAX_MSG_BYTES <= 55 and the key to
 * KEY_BYTES <= 64 (zero-padded to 64; longer keys must be hashed by the host
 * first, as RFC 2104 specifies).
 *
 * Byte protocol towards the core (2+1): clockinData high 2 cycles then low
 * 1 cycle per byte, waiting while busy; resultNext high 2 cycles then low 1
 * cycle per digest byte.  This is the protocol of the core's own testbench and
 * is the one that works whether the core outputs are sampled at or after the
 * clock edge; 1-cycle strobes need the latter (see test_hmac.py).
 *
 * Usage: hold key, msg and msg_len stable and pulse start for one cycle while
 * ready is high.  done pulses for one cycle when mac is valid; mac holds its
 * value until the next start or reset (it fills byte by byte during the
 * outer readout, so only read it after done).  start with msg_len > MAX_MSG_BYTES is
 * refused with a one-cycle err pulse.
 *
 * Secrets: the key is never stored; it is read from the key port while the
 * key blocks are streamed.  The inner digest is held only between the two
 * hashes and cleared as soon as it has been streamed into the outer hash.
 * rst_n clears every register here asynchronously.  The core's own reset is
 * synchronous, so zeroizing the core still needs a clock edge with rst_n low.
 */

`default_nettype none

module hmac_ctrl #(
    parameter KEY_BYTES     = 32,
    parameter MAX_MSG_BYTES = 55
) (
    input  wire                       clk,
    input  wire                       rst_n,

    // host side
    input  wire [8*KEY_BYTES-1:0]     key,      // byte 0 in the top bits
    input  wire [8*MAX_MSG_BYTES-1:0] msg,      // byte 0 in the top bits
    input  wire [5:0]                 msg_len,  // bytes, 0..MAX_MSG_BYTES
    input  wire                       start,
    output wire                       ready,
    output reg                        done,
    output reg                        err,
    output reg  [255:0]               mac,

    // shaman core side
    output reg  [7:0]                 core_data,
    output reg                        core_clockin,
    output reg                        core_start,
    output wire                       core_parallel,
    output reg                        core_result_next,
    input  wire                       core_busy,
    input  wire                       core_result_ready,
    input  wire [7:0]                 core_result_byte
);

  localparam S_IDLE      = 4'd0,
             S_START     = 4'd1,   // core start pulse
             S_START_GAP = 4'd2,
             S_WAIT_FREE = 4'd3,   // wait for ~busy before a byte
             S_STROBE_HI = 4'd4,   // clockinData high, 2 cycles
             S_WAIT_DROP = 4'd5,   // resultReady low: last block started
             S_WAIT_RISE = 4'd6,   // resultReady high: digest ready
             S_READ_PRE  = 4'd7,   // 2 cycles before the first digest byte
             S_READ_HI   = 4'd8,   // sample byte, resultNext high 2 cycles
             S_READ_LO   = 4'd9;   // resultNext low 1 cycle

  reg [3:0]   state;
  reg         outer;        // 0: inner hash, 1: outer hash
  reg [6:0]   idx;          // byte index within the 128-byte stream
  reg [4:0]   rd_idx;       // digest byte index
  reg         cnt;          // second cycle of a 2-cycle phase
  reg [9:0]   timeout;      // wait guard for resultReady
  reg [5:0]   len;          // latched msg_len
  reg [255:0] inner;        // inner digest: shifted in on readout, out on use

  assign ready = (state == S_IDLE);
  assign core_parallel = 1'b1;

  // ---- byte to stream at position idx ------------------------------------
  wire [6:0] pos     = idx - 7'd64;                     // position in block 2
  wire [5:0] dlen    = outer ? 6'd32 : len;             // data bytes in block 2
  wire [9:0] bitlen  = {4'd0, dlen} * 10'd8 + 10'd512;  // total message bits

  wire [7:0] key_byte = (idx < KEY_BYTES) ? key[8*KEY_BYTES-1 - 8*idx -: 8] : 8'h00;
  wire [7:0] pad_byte = outer ? 8'h5c : 8'h36;
  wire [7:0] msg_byte = (pos < MAX_MSG_BYTES) ? msg[8*MAX_MSG_BYTES-1 - 8*pos -: 8] : 8'h00;
  wire [7:0] data_byte = outer ? inner[255:248] : msg_byte;

  reg [7:0] stream_byte;
  always @* begin
    if (idx < 7'd64)
      stream_byte = key_byte ^ pad_byte;
    else if (pos < dlen)
      stream_byte = data_byte;
    else if (pos == dlen)
      stream_byte = 8'h80;
    else if (pos == 7'd62)
      stream_byte = {6'd0, bitlen[9:8]};
    else if (pos == 7'd63)
      stream_byte = bitlen[7:0];
    else
      stream_byte = 8'h00;
  end

  // ---- control FSM -------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state            <= S_IDLE;
      outer            <= 1'b0;
      idx              <= 7'd0;
      rd_idx           <= 5'd0;
      cnt              <= 1'b0;
      timeout          <= 10'd0;
      len              <= 6'd0;
      inner            <= 256'd0;
      mac              <= 256'd0;
      done             <= 1'b0;
      err              <= 1'b0;
      core_data        <= 8'h00;
      core_clockin     <= 1'b0;
      core_start       <= 1'b0;
      core_result_next <= 1'b0;
    end else begin
      done <= 1'b0;
      err  <= 1'b0;

      case (state)
        S_IDLE: begin
          if (start) begin
            if (msg_len > MAX_MSG_BYTES) begin
              err <= 1'b1;
            end else begin
              len   <= msg_len;
              mac   <= 256'd0;
              outer <= 1'b0;
              state <= S_START;
            end
          end
        end

        S_START: begin
          core_start <= 1'b1;
          idx        <= 7'd0;
          state      <= S_START_GAP;
        end

        S_START_GAP: begin
          core_start <= 1'b0;
          state      <= S_WAIT_FREE;
        end

        // clockinData rises here, falls two cycles later; the cycle after
        // that is spent back in S_WAIT_FREE (the 1 low cycle).
        S_WAIT_FREE: begin
          if (!core_busy) begin
            core_data    <= stream_byte;
            core_clockin <= 1'b1;
            cnt          <= 1'b0;
            state        <= S_STROBE_HI;
          end
        end

        S_STROBE_HI: begin
          cnt <= 1'b1;
          if (cnt) begin
            core_clockin <= 1'b0;
            if (outer && idx >= 7'd64 && idx < 7'd96)
              inner <= {inner[247:0], 8'h00};  // consumed byte is wiped
            if (idx == 7'd127) begin
              timeout <= 10'd0;
              state   <= S_WAIT_DROP;
            end else begin
              idx   <= idx + 7'd1;
              state <= S_WAIT_FREE;
            end
          end
        end

        S_WAIT_DROP: begin
          timeout <= timeout + 10'd1;
          if (!core_result_ready || &timeout) begin
            timeout <= 10'd0;
            state   <= S_WAIT_RISE;
          end
        end

        S_WAIT_RISE: begin
          if (core_result_ready)
            state <= S_READ_PRE;
        end

        S_READ_PRE: begin
          rd_idx <= 5'd0;
          cnt    <= 1'b0;
          state  <= S_READ_HI;
        end

        // first cycle: sample the byte and raise resultNext; second cycle:
        // keep it high; S_READ_LO then lowers it for one cycle.
        S_READ_HI: begin
          cnt <= 1'b1;
          if (!cnt) begin
            if (outer)
              mac <= {mac[247:0], core_result_byte};
            else
              inner <= {inner[247:0], core_result_byte};
            core_result_next <= 1'b1;
          end else begin
            state <= S_READ_LO;
          end
        end

        S_READ_LO: begin
          core_result_next <= 1'b0;
          cnt              <= 1'b0;
          if (rd_idx == 5'd31) begin
            if (!outer) begin
              outer <= 1'b1;
              state <= S_START;
            end else begin
              done  <= 1'b1;
              state <= S_IDLE;
            end
          end else begin
            rd_idx <= rd_idx + 5'd1;
            state  <= S_READ_HI;
          end
        end

        default: state <= S_IDLE;
      endcase
    end
  end

endmodule
