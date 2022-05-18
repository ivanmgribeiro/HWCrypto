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

package Test_Request_Generator;

`define MPARAMS m_id_, m_addr_, m_data_, m_awuser_, m_wuser_, m_buser_, m_aruser_, m_ruser_

import AXI :: *;
import Vector :: *;
import Test_Util :: *;
import SourceSink :: *;

interface Test_Request_Generator_IFC #( numeric type m_id_
                                      , numeric type m_addr_
                                      , numeric type m_data_
                                      , numeric type m_awuser_
                                      , numeric type m_wuser_
                                      , numeric type m_buser_
                                      , numeric type m_aruser_
                                      , numeric type m_ruser_
                                      );
    interface AXI4_Master #(`MPARAMS) axi_m;
    method Action set_verbosity (Bit #(4) new_verb);
    method Action reset;
endinterface

// input argument: a vector of Test_Elem to be done in sequence
module mkTest_Request_Generator #(Vector #(n_, Test_Elem) test_seq)
                                 (Test_Request_Generator_IFC #(`MPARAMS))
                                 provisos ( Add #(0, 64, m_data_)
                                          , Add #(0, 64, m_addr_)
                                          );
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);

    let shim <- mkAXI4ShimFF;
    // use rg_idx = n_ + 1 to mean we have finished the sequence
    Reg #(Bit #(TLog #(TAdd #(n_, 1)))) rg_idx <- mkReg (0);
    Reg #(Bit #(64)) rg_delay_counter <- mkReg (0);

    rule rl_loop (rg_delay_counter < test_seq[rg_idx].delay
                  && rg_idx < fromInteger (valueOf (n_)));
        rg_delay_counter <= rg_delay_counter + 1;
        if (rg_verbosity > 2) begin
            $display ( "%m Test Generator: rl_loop: rg_delay_counter: ", fshow (rg_delay_counter)
                     , " rg_idx: ", fshow (rg_idx));
        end
    endrule

    rule rl_send_aw (rg_idx < fromInteger (valueOf (n_))
                     && !test_seq[rg_idx].is_read
                     && shim.slave.aw.canPut
                     && shim.slave.w.canPut
                     && rg_delay_counter >= test_seq[rg_idx].delay);
        rg_delay_counter <= 0;
        rg_idx <= rg_idx + 1;

        let entry = test_seq[rg_idx];

        AXI4_AWFlit #(m_id_, m_addr_, m_awuser_) awflit = defaultValue;
        AXI4_WFlit #(m_data_, m_wuser_)   wflit  = defaultValue;
        awflit.awaddr = entry.addr;
        awflit.awsize = 8;
        wflit.wdata   = entry.data;

        if (rg_verbosity > 0) begin
            $display ("%m Test Generator: generating write request");
            $display ("    entry: ", fshow (entry));
            $display ("    awflit: ", fshow (awflit));
            $display ("    wflit: ", fshow (wflit));
        end

        shim.slave.aw.put (awflit);
        shim.slave.w.put (wflit);
    endrule

    rule rl_send_ar (rg_idx < fromInteger (valueOf (n_))
                     && test_seq[rg_idx].is_read
                     && shim.slave.ar.canPut
                     && rg_delay_counter <= test_seq[rg_idx].delay);
        rg_delay_counter <= 0;
        rg_idx <= rg_idx + 1;

        let entry = test_seq[rg_idx];

        AXI4_ARFlit #(m_id_, m_addr_, m_aruser_) arflit = defaultValue;
        arflit.araddr = entry.addr;
        arflit.arsize = 8;

        if (rg_verbosity > 0) begin
            $display ("%m Test Generator: generating read request");
            $display ("    entry: ", fshow (entry));
            $display ("    arflit: ", fshow (arflit));
        end

        shim.slave.ar.put (arflit);
    endrule

    rule rl_drop_bresp (shim.slave.b.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m Test Generator: dropping bresp: ", fshow (shim.slave.b.peek));
        end
        shim.slave.b.drop;
    endrule

    rule rl_drop_rresp (shim.slave.r.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m Test Generator: dropping rresp: ", fshow (shim.slave.r.peek));
        end
        shim.slave.r.drop;
    endrule

    rule rl_signal_finish (rg_idx >= fromInteger (valueOf (n_)));
        $display ("%m Test Generator: reached end of test");
        $finish(0);
    endrule

    interface axi_m = shim.master;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod

    method Action reset;
    endmethod
endmodule


endpackage
