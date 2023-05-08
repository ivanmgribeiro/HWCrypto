/*-
 * Copyright (c) 2022 Ivan Ribeiro
 * All rights reserved.
 *
 * This hardware was developed by University of Cambridge Computer Laboratory
 * (Department of Computer Science and Technology) under EPSRC award
 * EP/S030867/1 ("SIPP"); and by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

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
import SpecialFIFOs :: *;
import Vector :: *;
import Connectable :: *;
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
import AXI4_DMA_CHERI_Checker :: *;
`endif
`endif

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

(* synthesize *)
module mkHWCrypto64_Synth (HWCrypto_IFC #(4, 64, 64, 0, 0, 0, 0, 0,
                                          6, 64, 64, 0, 0, 0, 0, 0));
    let hwcrypto <- mkHWCrypto;
    return hwcrypto;
endmodule

(* synthesize *)
module mkHWCrypto64C_Synth (HWCrypto_IFC #(4, 64, 64, 0, 1, 0, 0, 1,
                                          6, 64, 64, 0, 1, 0, 0, 1));
    let hwcrypto <- mkHWCrypto;
    return hwcrypto;
endmodule

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
    FIFOF #(HWCrypto_Err) fifo_copy_end    <- mkUGFIFOF1;
    FIFOF #(Token) fifo_sha256_end  <- mkUGFIFOF1;
    FIFOF #(Token) fifo_hash_copy_end <- mkUGFIFOF;
    FIFOF #(Token) fifo_print_bram  <- mkUGFIFOF1;
    Reg #(Bool) rg_print_requested <- mkReg (False);
    Reg #(Bit #(32)) rg_bram_ctr <- mkReg (0);

    let ff_ctrl_to_reg <- mkBypassFIFOF;
    // this cannot be a bypass fifof because that would lead to a path from the register handler
    // to the controller and back to the register handler
    // TODO more explanation
    let ff_reg_to_ctrl <- mkFIFOF;
    let reg_handler <- mkHWCrypto_Reg_Handler (SourceSinkDiff { source: toSource (ff_ctrl_to_reg)
                                                              , sink  : toSink   (ff_reg_to_ctrl)});

    // TODO change 512
    BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_)) key_bram <- mkBRAMCore2 (512, False);
    BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_)) data_bram <- mkBRAMCore2 (512, False);
    let ff_ctrl_to_xor_ctrl <- mkBypassFIFOF;
    let ff_ctrl_to_pad_ctrl <- mkBypassFIFOF;
    BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_)) key_bram_xor <- mkBRAM_DP_XOR ( key_bram
                                                                              , toSource (ff_ctrl_to_xor_ctrl)
                                                                              , toSource (ff_ctrl_to_pad_ctrl)
                                                                              );

    Wire #(Bit #(TLog #(2))) dw_bram_index <- mkDWire (0);
    Vector #(2, BRAM_DUAL_PORT #(Bit #(32), Bit #(m_data_))) v_brams = newVector;
    v_brams[0] = key_bram_xor;
    v_brams[1] = data_bram;

    let bram <- mkHWCrypto_BRAM_DP_Mux (v_brams, dw_bram_index);



    let ff_ctrl_to_data_mover <- mkBypassFIFOF;
    let ff_data_mover_to_ctrl <- mkBypassFIFOF;
    HWCrypto_Data_Mover_IFC #(m_id_, m_addr_, m_data_,
                              m_awuser_, m_wuser_,
                              // TODO find a cleaner way of doing this
                              TAdd #(
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
                                     1
`else
                                     0
`endif
`else
                                     0
`endif

                                      , m_buser_),
                              m_aruser_,
                              TAdd #(
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
                                     1
`else
                                     0
`endif
`else
                                     0
`endif
                                      , m_ruser_)
                              )
        data_mover <- mkHWCrypto_Data_Mover ( bram.a
                                            , SourceSinkDiff { source: toSource (ff_ctrl_to_data_mover)
                                                             , sink  : toSink   (ff_data_mover_to_ctrl)
                                                             }
                                            );

    let ff_ctrl_to_sha256 <- mkBypassFIFOF;
    let ff_sha256_to_ctrl <- mkBypassFIFOF;
    HWCrypto_SHA256_IFC sha256 <- mkHWCrypto_SHA256 ( bram.b
                                                    , SourceSinkDiff { source: toSource (ff_ctrl_to_sha256)
                                                                     , sink  : toSink   (ff_sha256_to_ctrl)
                                                                     }
                                                    );

    let ff_ctrl_to_hash_copy <- mkBypassFIFOF;
    let ff_hash_copy_to_ctrl <- mkBypassFIFOF;
    let hash_copy <- mkCopy_Hash_To_BRAM ( sha256.hash_regs
                                         , bram.a
                                         , SourceSinkDiff { source: toSource (ff_ctrl_to_hash_copy)
                                                          , sink  : toSink   (ff_hash_copy_to_ctrl)
                                                          }
                                         );

    HWCrypto_Controller_IFC #(2) controller
        <- mkHWCrypto_Controller ( SourceSinkDiff { source: toSource (ff_reg_to_ctrl)
                                                  , sink  : toSink   (ff_ctrl_to_reg)}
                                 , SourceSinkDiff { source: toSource (ff_data_mover_to_ctrl)
                                                  , sink  : toSink   (ff_ctrl_to_data_mover)}
                                 , SourceSinkDiff { source: toSource (ff_sha256_to_ctrl)
                                                  , sink  : toSink   (ff_ctrl_to_sha256)}
                                 , SourceSinkDiff { source: toSource (ff_hash_copy_to_ctrl)
                                                  , sink  : toSink   (ff_ctrl_to_hash_copy)}
                                 , toSink (ff_ctrl_to_pad_ctrl)
                                 , toSink (ff_ctrl_to_xor_ctrl)
                                 , reg_handler.regs
                                 );



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

    let data_mover_axi_m = data_mover.axi_m;
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
    HWCrypto_Ptr cur_cap = controller.cur_cap;
    CHERI_Checker_IFC #(`MPARAMS) cheri_checker <- mkCHERI_Checker;
    mkConnection ( cheri_checker.slave
                 , fn_extend_ar_aw_user_fields (data_mover.axi_m, cur_cap));
    data_mover_axi_m = cheri_checker.master;
`endif
`endif

    interface axi_s = reg_handler.axi_s;

    interface axi_m = data_mover_axi_m;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
        reg_handler.set_verbosity (new_verb);
        data_mover.set_verbosity (new_verb);
        sha256.set_verbosity (new_verb);
        controller.set_verbosity (new_verb);
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
        cheri_checker.set_verbosity (new_verb);
`endif
`endif
    endmethod

    method Action reset;
    endmethod
    method interrupt = False;
endmodule

`undef MPARAMS
`undef SPARAMS
endpackage
