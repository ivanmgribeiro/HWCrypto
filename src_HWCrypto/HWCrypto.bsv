package HWCrypto;

`define MPARAMS m_id_, m_addr_, m_data_, m_awuser_, m_wuser_, m_buser_, m_aruser_, m_ruser_
`define SPARAMS s_id_, s_addr_, s_data_, s_awuser_, s_wuser_, s_buser_, s_aruser_, s_ruser_

import AXI :: *;
import HWCrypto_Reg_Handler :: *;
import HWCrypto_Data_Mover :: *;
import HWCrypto_Types :: *;
import SourceSink :: *;
import BRAMCore :: *;
import FIFOF :: *;

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

                           , Add#(0, 64, m_addr_)
                           );
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    FIFOF #(Token) fifo_tkn <- mkFIFOF1;
    FIFOF #(Token) fifo_dm_tkn <- mkFIFOF1;
    Reg #(Bool) rg_fetch_started <- mkReg (False);

    let reg_handler <- mkHWCrypto_Reg_Handler (toSink (fifo_tkn));
    // TODO change 512
    BRAM_DUAL_PORT_BE #(Bit #(32), Bit #(m_data_), TDiv #(m_data_, 8)) bram <- mkBRAMCore2BE (512, False);
    let data_mover <- mkHWCrypto_Data_Mover (bram.a, toSink (fifo_dm_tkn));

    //Reg #(Bit #(64)) rg_counter <- mkReg (0);
    //rule rl_test;
    //    rg_counter <= rg_counter + 1;
    //    $display ("counter: ", fshow (rg_counter));
    //    data_mover.request (zeroExtend (rg_counter[63:8]) , 0, BUS2BRAM, zeroExtend (rg_counter[7:0]));
    //endrule

    //rule rl_debug;
    //    $display ("fifo_tkn.notEmpty: ", fshow (fifo_tkn.notEmpty));
    //    $display ("fifo_tkn.notFull: ", fshow (fifo_tkn.notFull));
    //endrule

    rule rl_start_fetch (fifo_tkn.notEmpty
                         && !rg_fetch_started);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto rl_start_fetch");
            $display ( "    requesting data move, parameters -"
                     , "  addr: ", fshow (reg_handler.data_ptr)
                     , "  len: ", fshow (reg_handler.data_len));
        end
        data_mover.request (reg_handler.data_ptr, 0, BUS2BRAM, reg_handler.data_len);
        rg_fetch_started <= True;
    endrule

    Reg #(Bit #(32)) rg_bram_ctr <- mkReg (0);
    rule rl_print_bram (fifo_dm_tkn.notEmpty);
        rg_bram_ctr <= rg_bram_ctr + 1;
        if (rg_bram_ctr != 0) begin
            $display ("bram addr: ", fshow (rg_bram_ctr - 1), "  data: ", fshow (bram.b.read));
        end
        bram.b.put (0, rg_bram_ctr, ?);
    endrule


    interface axi_s = reg_handler.axi_s;

    interface axi_m = data_mover.axi_m;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
        reg_handler.set_verbosity (new_verb);
        data_mover.set_verbosity (new_verb);
    endmethod

    method Action reset;
    endmethod
    method interrupt = False;
endmodule

`undef MPARAMS
`undef SPARAMS
endpackage
