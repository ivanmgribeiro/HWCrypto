package HWCrypto_Reg_Handler;

import HWCrypto_Types :: *;
import AXI :: *;
import SourceSink :: *;

`define SPARAMS s_id_, s_addr_, s_data_, s_awuser_, s_wuser_, s_buser_, s_aruser_, s_ruser_

interface HWCrypto_Reg_Handler_IFC #( numeric type s_id_
                                    , numeric type s_addr_
                                    , numeric type s_data_
                                    , numeric type s_awuser_
                                    , numeric type s_wuser_
                                    , numeric type s_buser_
                                    , numeric type s_aruser_
                                    , numeric type s_ruser_
                                    );
    interface AXI4_Slave #(`SPARAMS) axi_s;
    // TODO make this 64 general
    (* always_ready *) method HWCrypto_Regs regs;
    method Action set_verbosity (Bit #(4) new_verb);
    method Action reset;
endinterface

/*
 *  Behaviour:
 *   +  If the HWCrypto is idle, allow reads and writes as normal
 *   +  If the HWCrypto is not idle, allow reads and ignore writes (ie send back
 *      write responses, but don't write to registers.
 *   +  Writes must be s_data_ sized
 *   +  Writes must be aligned to the write size
 *   +  Writes must be single-flit
 *   +  Both the AW and W streams must be valid in order to be processed
 *
 *  Interface:
 *   +  If the Sink that is passed as an argument can be enqueued into,
 *      then the HWCrypto is idle. Otherwise it is not.
 */
// TODO remove restriction for addr and data to be 64b
module mkHWCrypto_Reg_Handler #(Sink #(Token) snk)
                               (HWCrypto_Reg_Handler_IFC #(`SPARAMS))
                               provisos ( Add #(0, 64, s_addr_)
                                        , Add #(0, 64, s_data_)
                                        );
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);

    AXI4_Shim #(`SPARAMS) shim <- mkAXI4ShimFF;

    Reg #(Bit #(64)) rg_data_ptr <- mkRegU;
    Reg #(Bit #(64)) rg_data_len <- mkRegU;
    Reg #(Bit #(64)) rg_key_ptr  <- mkRegU;
    Reg #(Bit #(64)) rg_key_len  <- mkRegU;
    Reg #(Bit #(64)) rg_dest_ptr <- mkRegU;

    rule rl_handle_write (shim.master.aw.canPeek
                          && shim.master.w.canPeek
                          && shim.master.b.canPut);
        shim.master.aw.drop;
        shim.master.w.drop;
        let awflit = shim.master.aw.peek;
        let wflit = shim.master.w.peek;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto: received write request");
            $display ("    awflit: ", fshow (awflit));
            $display ("    wflit: ", fshow (wflit));
        end

        // TODO check range
        let is_valid_addr = awflit.awaddr[2:0] == 0;
        let is_valid_size = awflit.awsize == 8;
        let is_valid_len = awflit.awlen == 0;
        // TODO make this more general
        let index = awflit.awaddr[5:3];
        let new_val = wflit.wdata;

        if (is_valid_addr && is_valid_size && is_valid_len) begin
            if (rg_verbosity > 0) begin
                $display ("    request is valid");
            end
            if (snk.canPut) begin
                if (rg_verbosity > 0) begin
                    $display ("    HWCrypto is idle; writing to register with index ", fshow (index));
                    $display ("        value to write: ", fshow (new_val));
                end
                if (index == 0)      rg_data_ptr <= new_val;
                else if (index == 1) rg_data_len <= new_val;
                else if (index == 2) rg_key_ptr  <= new_val;
                else if (index == 3) rg_key_len  <= new_val;
                else if (index == 4) rg_dest_ptr <= new_val;
                else if (index == 5) begin
                    if (rg_verbosity > 0) begin
                        $display ("    Triggering next stage");
                    end
                    snk.put (?); // trigger next stage
                end
            end

            AXI4_BFlit #(s_id_, s_buser_) bflit = AXI4_BFlit { bid: awflit.awid
                                                              , bresp: OKAY
                                                              , buser: 0
                                                              };
            if (rg_verbosity > 1) begin
                $display ("    response: ", fshow (bflit));
            end
            shim.master.b.put (bflit);
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    request is invalid");
                $display ("        is_valid_addr: ", fshow (is_valid_addr));
                $display ("        is_valid_size: ", fshow (is_valid_size));
                $display ("        is_valid_len: ", fshow (is_valid_len));
            end
            AXI4_BFlit #(s_id_, s_buser_) bflit = AXI4_BFlit { bid: awflit.awid
                                                              , bresp: OKAY
                                                              , buser: 0
                                                              };
            if (rg_verbosity > 1) begin
                $display ("    response: ", fshow (bflit));
            end
            shim.master.b.put (bflit);
        end
    endrule

    rule rl_handle_read (shim.master.ar.canPeek
                         && shim.master.r.canPut);
        shim.master.ar.drop;
        let arflit = shim.master.ar.peek;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto: received read request");
            $display ("    arflit: ", fshow (arflit));
        end

        // TODO check range
        let is_valid_addr = arflit.araddr[2:0] == 0;
        let is_valid_size = arflit.arsize == 8;
        let is_valid_len = arflit.arlen == 0;
        // TODO make this more general
        let index = arflit.araddr[5:3];
        let data = ?;

        if (is_valid_addr && is_valid_size && is_valid_len) begin
            if (rg_verbosity > 0) begin
                $display ("    request is valid");
                $display ("    reading from index ", fshow (index));
            end
            if (index == 0)      data = rg_data_ptr;
            else if (index == 1) data = rg_data_len;
            else if (index == 2) data = rg_key_ptr;
            else if (index == 3) data = rg_key_len;
            else if (index == 4) data = rg_dest_ptr;
            else if (index == 5) data = zeroExtend (pack (!snk.canPut));
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    request is invalid");
                $display ("        is_valid_addr: ", fshow (is_valid_addr));
                $display ("        is_valid_size: ", fshow (is_valid_size));
                $display ("        is_valid_len: ", fshow (is_valid_len));
            end
        end

        // TODO return something else if not valid
        AXI4_RFlit #(s_id_, s_data_, s_ruser_) rflit = AXI4_RFlit { rid:   arflit.arid
                                                                   , rdata: data
                                                                   , rresp: OKAY
                                                                   , rlast: True
                                                                   , ruser: 0
                                                                   };
        if (rg_verbosity > 0) begin
            $display ("    response: ", fshow (rflit));
        end
        shim.master.r.put(rflit);
    endrule


    interface axi_s = shim.slave;

    method HWCrypto_Regs regs;
        return HWCrypto_Regs { data_ptr: rg_data_ptr
                             , data_len: rg_data_len
                             , key_ptr:  rg_key_ptr
                             , key_len:  rg_key_len
                             , dest_ptr: rg_dest_ptr
                             };
    endmethod

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod

    method Action reset;
    endmethod
endmodule

`undef SPARAMS

endpackage
