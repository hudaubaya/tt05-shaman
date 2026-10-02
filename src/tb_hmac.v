`default_nettype none
`timescale 1ns/1ps

/*
 * hmac_ctrl driving the shaman core through its TinyTapeout pins, for
 * test_hmac_ctrl.py.  Run with:  make HMAC=yes
 */
module tb_hmac ();

    initial begin
        $dumpfile ("tb_hmac.vcd");
        $dumpvars (0, tb_hmac);
        #1;
    end

    localparam KEY_BYTES     = 32;
    localparam MAX_MSG_BYTES = 55;

    reg                        clk;
    reg                        rst_n;
    reg  [8*KEY_BYTES-1:0]     key;
    reg  [8*MAX_MSG_BYTES-1:0] msg;
    reg  [5:0]                 msg_len;
    reg                        start;
    wire                       ready;
    wire                       done;
    wire                       err;
    wire [255:0]               mac;

    wire [7:0] core_data;
    wire       core_clockin;
    wire       core_start;
    wire       core_parallel;
    wire       core_result_next;
    wire [7:0] uo_out;
    wire [7:0] uio_out;
    wire [7:0] uio_oe;

    hmac_ctrl #(
        .KEY_BYTES(KEY_BYTES),
        .MAX_MSG_BYTES(MAX_MSG_BYTES)
    ) ctrl (
        .clk              (clk),
        .rst_n            (rst_n),
        .key              (key),
        .msg              (msg),
        .msg_len          (msg_len),
        .start            (start),
        .ready            (ready),
        .done             (done),
        .err              (err),
        .mac              (mac),
        .core_data        (core_data),
        .core_clockin     (core_clockin),
        .core_start       (core_start),
        .core_parallel    (core_parallel),
        .core_result_next (core_result_next),
        .core_busy        (uio_out[4]),
        .core_result_ready(uio_out[0]),
        .core_result_byte (uo_out)
    );

    // pin mapping as in tb.v
    tt_um_psychogenic_shaman core (
        .ui_in  (core_data),
        .uo_out (uo_out),
        .uio_in ({core_clockin, core_start, 2'b00, core_result_next, core_parallel, 2'b00}),
        .uio_out(uio_out),
        .uio_oe (uio_oe),
        .ena    (1'b1),
        .clk    (clk),
        .rst_n  (rst_n)
    );

endmodule
