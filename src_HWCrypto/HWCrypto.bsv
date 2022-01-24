package HWCrypto;

`define MPARAMS m_id_, m_addr_, m_data_, m_awuser_, m_wuser_, m_buser_, m_aruser_, m_ruser_
`define SPARAMS s_id_, s_addr_, s_data_, s_awuser_, s_wuser_, s_buser_, s_aruser_, s_ruser_

import AXI :: *;
import HWCrypto_Reg_Handler :: *;
import HWCrypto_Data_Mover :: *;
import HWCrypto_Types :: *;
import HWCrypto_SHA256 :: *;
import SourceSink :: *;
import BRAMCore :: *;
import FIFOF :: *;
import Connectable :: *;

interface HWCrypto_IFC #( // master interface parameters
                          numeric type m_id_
                        , numeric type m_addr_
                        , numeric type m_data_
                        , numeric type m_awuser_
                        , numeric type m_wuser_
                        , numeric type m_buser_
                        , numeric type m_aruser_
                        , numeric type m_ruser_
                        // slave interface parameters
                        , numeric type s_id_
                        , numeric type s_addr_
                        , numeric type s_data_
                        , numeric type s_awuser_
                        , numeric type s_wuser_
                        , numeric type s_buser_
                        , numeric type s_aruser_
                        , numeric type s_ruser_
                        );
    interface AXI4_Master #(`MPARAMS) axi_m;

    interface AXI4_Slave #(`SPARAMS) axi_s;

    (* always_ready *) method Bool interrupt;

    method Action set_verbosity (Bit #(4) new_verb);
    method Action reset;
endinterface

// TODO remove restriction for addr and data to be 64b
module mkHWCrypto (HWCrypto_IFC #(`MPARAMS, `SPARAMS))
                  provisos ( Add #(0, 64, s_addr_)
                           , Add #(0, 64, s_data_)
                           , Add#(a__, TLog#(TDiv#(m_data_, 8)), m_addr_)
                           , Add#(b__, 10, m_addr_)
                           , Add#(c__, TLog#(TAdd#(1, TLog#(TDiv#(m_data_, 8)))), 3)
                           , Add#(d__, 3, TLog#(TDiv#(m_data_, 8)))
                           , Add#(e__, TLog#(TDiv#(m_data_, 8)), 64)
                           , Mul#(TDiv#(m_data_, TDiv#(m_data_, 8)), TDiv#(m_data_, 8), m_data_)
                           , Add#(f__, 1, TDiv#(m_data_, 8))
                           // TODO bsc-requested. seems odd
                           , Add#(g__, 8, TMul#(TDiv#(m_data_, 8), 8))
                           , Add#(m_data_, h__, TMul#(m_data_, 2))
                           , Add#(i__, TMul#(TDiv#(m_data_, 8), 8), TMul#(m_data_, 2))

                           // TODO relax this?

                           , Add#(0, 64, m_data_)
                           , Add#(0, 64, m_addr_)
                           );
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    FIFOF #(Token) fifo_reg_trigger <- mkUGFIFOF1;
    FIFOF #(Token) fifo_copy_end    <- mkUGFIFOF1;
    FIFOF #(Token) fifo_sha256_end  <- mkUGFIFOF1;
    FIFOF #(Token) fifo_print_bram  <- mkUGFIFOF1;
    Reg #(Bool) rg_print_requested <- mkReg (False);
    Reg #(Bit #(32)) rg_bram_ctr <- mkReg (0);

    let reg_handler <- mkHWCrypto_Reg_Handler (toSink (fifo_reg_trigger));
    // TODO change 512
    BRAM_DUAL_PORT_BE #(Bit #(32), Bit #(m_data_), TDiv #(m_data_, 8)) bram <- mkBRAMCore2BE (512, False);
    HWCrypto_Data_Mover_IFC #(`MPARAMS, 32) data_mover <- mkHWCrypto_Data_Mover (bram.a, toSink (fifo_copy_end));
    HWCrypto_SHA256_IFC #(32) sha256 <- mkHWCrypto_SHA256 (bram.b, toSink (fifo_sha256_end));

    rule rl_pipe;
        let enq_bram_print_req = False;
        if (rg_verbosity > 0 && !fifo_print_bram.notEmpty) begin
            $display ("%m HWCrypto rl_pipe");
        end
        if (fifo_reg_trigger.notEmpty && data_mover.is_ready) begin
            // request print of BRAM if it's not already been requested
            if (rg_verbosity > 1 && fifo_print_bram.notFull && !rg_print_requested) begin
                if (!rg_print_requested) begin
                    $display ("    printing BRAM contents");
                    enq_bram_print_req = True;
                end
            end
            // if we have high verbosity, wait until the bram is finished printing
            if ((rg_verbosity > 1 && rg_print_requested && !fifo_print_bram.notEmpty)
                 || rg_verbosity <= 1) begin
                // TODO this might need to change if we want to use different parts of the BRAM
                let bram_addr = 0;
                data_mover.request (reg_handler.data_ptr, bram_addr, BUS2BRAM, reg_handler.data_len);
                fifo_reg_trigger.deq;
                if (rg_verbosity > 0) begin
                    $display ( "    making data mover request, parameters -"
                             , "  addr: ", fshow (reg_handler.data_ptr)
                             , "  len: ", fshow (reg_handler.data_len)
                             , "  bram addr: ", fshow (bram_addr)
                             , "  dir: ", fshow (BUS2BRAM));
                end
            end
        end
        if (fifo_copy_end.notEmpty && sha256.is_ready) begin
            // request print of BRAM if it's not already been requested
            if (rg_verbosity > 1 && fifo_print_bram.notFull && !rg_print_requested) begin
                if (!rg_print_requested) begin
                    $display ("    printing BRAM contents");
                    enq_bram_print_req = True;
                end
            end
            // if we have high verbosity, wait until the bram is finished printing
            if ((rg_verbosity > 1 && rg_print_requested && !fifo_print_bram.notEmpty)
                 || rg_verbosity <= 1) begin
                let bram_addr = 0;
                let bram_len = 512;
                let is_last = True;
                sha256.request (bram_addr, bram_len, is_last);
                if (rg_verbosity > 0) begin
                    $display ( "    making sha256 request, parameters -"
                             , "  addr: ", fshow (bram_addr)
                             , "  len: ", fshow (bram_len)
                             , "  is_last: ", fshow (is_last));
                end
            end
        end
        if (fifo_sha256_end.notEmpty) begin
            // request print of BRAM if it's not already been requested
            if (rg_verbosity > 1 && fifo_print_bram.notFull && !rg_print_requested) begin
                if (!rg_print_requested) begin
                    $display ("    printing BRAM contents");
                    enq_bram_print_req = True;
                end
            end
            // if we have high verbosity, wait until the bram is finished printing
            if ((rg_verbosity > 1 && rg_print_requested && !fifo_print_bram.notEmpty)
                || rg_verbosity <= 1) begin
            end
        end

        if (rg_verbosity > 1) begin
            if (enq_bram_print_req) begin
                rg_bram_ctr <= 0;
                fifo_print_bram.enq (?);
                rg_print_requested <= True;
            end else if (rg_print_requested && !fifo_print_bram.notEmpty) begin
                rg_print_requested <= False;
            end
        end
    endrule


    Reg #(Bool) rg_print_bram <- mkReg (False);
    Reg #(Bool) rg_print_bram_finished <- mkReg (False);

    rule rl_print_bram (fifo_print_bram.notEmpty);
        if (rg_bram_ctr != 0) begin
            $display ("bram addr: ", fshow (rg_bram_ctr - 1), "  data: ", fshow (bram.b.read));
        end
        if (rg_bram_ctr < 64) begin
            rg_bram_ctr <= rg_bram_ctr + 1;
            bram.b.put (0, rg_bram_ctr, ?);
        end else begin
            fifo_print_bram.deq;
        end
    endrule


    interface axi_s = reg_handler.axi_s;

    interface axi_m = data_mover.axi_m;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
        reg_handler.set_verbosity (new_verb);
        data_mover.set_verbosity (new_verb);
        sha256.set_verbosity (new_verb);
    endmethod

    method Action reset;
    endmethod
    method interrupt = False;
endmodule

`undef MPARAMS
`undef SPARAMS
endpackage
