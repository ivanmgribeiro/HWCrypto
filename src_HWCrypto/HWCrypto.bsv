package HWCrypto;

`define MPARAMS m_id_, m_addr_, m_data_, m_awuser_, m_wuser_, m_buser_, m_aruser_, m_ruser_
`define SPARAMS s_id_, s_addr_, s_data_, s_awuser_, s_wuser_, s_buser_, s_aruser_, s_ruser_

import AXI :: *;
import HWCrypto_Reg_Handler :: *;
import HWCrypto_Data_Mover :: *;
import HWCrypto_Types :: *;
import HWCrypto_SHA256 :: *;
import HWCrypto_Controller :: *;
import HWCrypto_Utils :: *;
import SourceSink :: *;
import BRAMCore :: *;
import FIFOF :: *;
import Vector :: *;
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
    BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_)) key_bram <- mkBRAMCore2 (512, False);
    BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_)) data_bram <- mkBRAMCore2 (512, False);
    BRAM_DP_XOR_IFC #(Bit #(32), Bit #(m_data_)) key_bram_xor <- mkBRAM_DP_XOR (key_bram);
    Wire #(Bit #(TLog #(2))) dw_bram_index <- mkDWire (0);
    Vector #(2, BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_))) v_brams = newVector;
    v_brams[0] = key_bram_xor.bram;
    v_brams[1] = data_bram;

    let bram <- mkHWCrypto_BRAM_DP_Mux (v_brams, dw_bram_index);



    HWCrypto_Data_Mover_IFC #(`MPARAMS, 32) data_mover <- mkHWCrypto_Data_Mover (bram.a, toSink (fifo_copy_end));
    HWCrypto_SHA256_IFC #(32) sha256 <- mkHWCrypto_SHA256 (bram.b, toSink (fifo_sha256_end));
    HWCrypto_Controller_IFC #(m_addr_, 32, m_data_, 2) controller
        <- mkHWCrypto_Controller ( toSource (fifo_reg_trigger)
                                 , data_mover.is_ready
                                 , toSource (fifo_copy_end)
                                 , sha256.is_ready
                                 , toSource (fifo_sha256_end)
                                 , reg_handler.regs
                                 );

    rule rl_forward_dm_req;
        if (isValid (controller.data_mover_req)) begin
            data_mover.request (controller.data_mover_req.Valid);
        end
    endrule

    rule rl_forward_sha256_req;
        if (isValid (controller.sha256_req)) begin
            sha256.request (controller.sha256_req.Valid);
        end
    endrule

    rule rl_forward_pad_ctrl (isValid (controller.key_pad_ctrl));
        let ctrl = controller.key_pad_ctrl.Valid;
        key_bram_xor.set_pad (tpl_1 (ctrl), tpl_2 (ctrl));
    endrule

    rule rl_forward_xor_ctrl (isValid (controller.key_xor_ctrl));
        key_bram_xor.set_xor (controller.key_xor_ctrl.Valid);
    endrule

    rule rl_forward_bram_index;
        dw_bram_index <= controller.bram_index;
    endrule

    Reg #(Bool) rg_print_bram <- mkReg (False);
    Reg #(Bool) rg_print_bram_finished <- mkReg (False);

    rule rl_print_bram (fifo_print_bram.notEmpty);
        if (rg_bram_ctr != 0) begin
            $display ("bram addr: ", fshow (rg_bram_ctr - 1), "  data: ", fshow (bram.b.read));
        end
        if (rg_bram_ctr < 64) begin
            rg_bram_ctr <= rg_bram_ctr + 1;
            bram.b.put (False, rg_bram_ctr, ?);
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
        controller.set_verbosity (new_verb);
    endmethod

    method Action reset;
    endmethod
    method interrupt = False;
endmodule

`undef MPARAMS
`undef SPARAMS
endpackage
