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

package HWCrypto_Utils;

import BRAMCore :: *;
import Vector :: *;
import SourceSink :: *;
import Connectable :: *;
import HWCrypto_Types :: *;
import AXI4 :: *;
import FIFOF :: *;
import SpecialFIFOs :: *;

module mkBRAM_PORT_XOR #( BRAM_PORT #(addr_t_, data_t_) bram_i
                        , Source #(Bit #(data_t_sz_)) s_xor_ctrl
                        , Source #(Tuple2 #(Bool, Bit #(key_pad_start_sz_))) s_pad_ctrl)
                        (BRAM_PORT #(addr_t_, data_t_))
                        provisos ( Bits#(data_t_, data_t_sz_)
                                 , Bits #(addr_t_, addr_t_sz_)
                                 , Add #(a__, TLog #(TDiv #(data_t_sz_, 8)), TLog #(data_t_sz_))
                                 , NumAlias #(key_pad_start_sz_, TAdd #(addr_t_sz_, TLog #(TDiv #(data_t_sz_, 8))))
                                 );
    Reg #(Bit #(SizeOf #(data_t_))) rg_xor <- mkReg (0);
    Reg #(Bool) rg_use_xor <- mkRegU;
    Reg #(Bool) rg_pad_set <- mkReg (False);
    Reg #(Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8))))) rg_pad_start <- mkRegU;
    Reg #(Bit #(SizeOf #(data_t_))) rg_mask <- mkReg (~0);

    rule rl_handle_xor_request (s_xor_ctrl.canPeek);
        rg_xor <= s_xor_ctrl.peek;
        s_xor_ctrl.drop;
    endrule

    rule rl_handle_pad_request (s_pad_ctrl.canPeek);
        rg_pad_set   <= tpl_1(s_pad_ctrl.peek);
        rg_pad_start <= tpl_2(s_pad_ctrl.peek);
        s_pad_ctrl.drop;
    endrule

    method Action put (Bool write, addr_t_ addr, data_t_ data);
        bram_i.put (write, addr, data);
        if (!write) begin
            if (pack (addr) > fromInteger ((512/valueOf (SizeOf #(data_t_))) - 1)) begin
                // return the raw bits after bit 512
                rg_mask <= ~0;
                rg_use_xor <= False;
            end else if (pack (addr) > truncateLSB (rg_pad_start)) begin
                Bit #(SizeOf #(addr_t_)) truncatedval = truncateLSB (rg_pad_start);
                rg_mask <= 0;
                rg_use_xor <= True;
            end else if (pack (addr) == truncateLSB (rg_pad_start)) begin
                Bit #(TLog #(TDiv #(SizeOf #(data_t_), 8))) lsb = truncate (rg_pad_start);
                Bit #(TLog #(SizeOf #(data_t_))) shamt = zeroExtend (lsb) << 3;
                rg_mask <= ~(~0 << shamt);
                rg_use_xor <= True;
            end else begin
                rg_mask <= ~0;
                rg_use_xor <= True;
            end
        end
    endmethod
    method data_t_ read;
        return unpack ((pack (bram_i.read) & (rg_pad_set ? rg_mask : ~0)) ^ (rg_use_xor ? rg_xor : 0));
    endmethod

endmodule

module mkBRAM_DP_XOR #( BRAM_DUAL_PORT #(addr_t_, data_t_) bram_i
                      , Source #(Bit #(data_t_sz_)) s_xor_ctrl
                      , Source #(Tuple2 #(Bool, Bit #(key_pad_start_sz_))) s_pad_ctrl)
                      (BRAM_DUAL_PORT #(addr_t_, data_t_))
                      provisos ( Bits #(addr_t_, addr_t_sz_)
                               , Bits #(data_t_, data_t_sz_)
                               , Add#(a__, TLog#(TDiv#(data_t_sz_, 8)), TLog#(data_t_sz_))
                               , NumAlias #(key_pad_start_sz_, TAdd #(addr_t_sz_, TLog #(TDiv #(data_t_sz_, 8))))
                               );

    FIFOF #(Bit #(data_t_sz_)) ff_xor_ctrl_a <- mkBypassFIFOF;
    FIFOF #(Tuple2 #(Bool, Bit #(key_pad_start_sz_))) ff_pad_ctrl_a <- mkBypassFIFOF;
    FIFOF #(Bit #(data_t_sz_)) ff_xor_ctrl_b <- mkBypassFIFOF;
    FIFOF #(Tuple2 #(Bool, Bit #(key_pad_start_sz_))) ff_pad_ctrl_b <- mkBypassFIFOF;

    let bram_a <- mkBRAM_PORT_XOR (bram_i.a, debugSource (toSource (ff_xor_ctrl_a), $format("ff_xor_ctrl_A")), debugSource (toSource (ff_pad_ctrl_a), $format("ff_pad_ctrl_a")));
    let bram_b <- mkBRAM_PORT_XOR (bram_i.b, debugSource (toSource (ff_xor_ctrl_b), $format("ff_xor_ctrl_b")), debugSource (toSource (ff_pad_ctrl_b), $format("ff_pad_ctrl_b")));

    rule rl_handle_xor_request (s_xor_ctrl.canPeek
                                && ff_xor_ctrl_a.notFull
                                && ff_xor_ctrl_b.notFull);
        ff_xor_ctrl_a.enq (s_xor_ctrl.peek);
        ff_xor_ctrl_b.enq (s_xor_ctrl.peek);
        s_xor_ctrl.drop;
    endrule

    rule rl_handle_pad_request (s_pad_ctrl.canPeek
                                && ff_pad_ctrl_a.notFull
                                && ff_pad_ctrl_b.notFull);
        ff_pad_ctrl_a.enq (s_pad_ctrl.peek);
        ff_pad_ctrl_b.enq (s_pad_ctrl.peek);
        s_pad_ctrl.drop;
    endrule

    interface a = bram_a;
    interface b = bram_b;
endmodule

module mkHWCrypto_BRAM_Mux #( Vector #(n_, BRAM_PORT #(addr_t_, data_t_)) v_brams
                            , Bit #(TLog #(n_)) index)
                            (BRAM_PORT #(addr_t_, data_t_));
    method Action put (Bool write, addr_t_ addr, data_t_ data);
        v_brams[index].put (write, addr, data);
    endmethod
    method data_t_ read = v_brams[index].read;
endmodule

module mkHWCrypto_BRAM_DP_Mux #( Vector #(n_, BRAM_DUAL_PORT #(addr_t_, data_t_)) v_brams
                               , Bit #(TLog #(n_)) index)
                               (BRAM_DUAL_PORT #(addr_t_, data_t_));
    Vector #(n_, BRAM_PORT #(addr_t_, data_t_)) as = newVector;
    Vector #(n_, BRAM_PORT #(addr_t_, data_t_)) bs = newVector;
    for (Integer i = 0; i < valueOf (n_); i = i+1) begin
        as[i] = v_brams[i].a;
        bs[i] = v_brams[i].b;
    end
    let port_a <- mkHWCrypto_BRAM_Mux (as, index);
    let port_b <- mkHWCrypto_BRAM_Mux (bs, index);
    interface a = port_a;
    interface b = port_b;
endmodule

function Bit #(TMul #(n_, 8)) fn_rev_byte_order (Bit #(TMul #(n_, 8)) in)
    provisos (Add#(z__, 8, TMul#(n_, 8)));
    Bit #(TMul #(n_, 8)) res = 0;
    for (Integer i = 0; i < valueOf (TMul #(n_, 8)); i = i+8) begin
        Bit #(8) val = truncate (in >> fromInteger (valueOf (TMul #(n_, 8)) - i - 8));
        res[i + 7:i] = val;
    end
    return truncateLSB (res);
endfunction

module mkCopy_Hash_To_BRAM #( Vector #(n_, Bit #(rg_sz_)) v_rg_data
                            , BRAM_PORT #(Bit #(addr_sz_), Bit #(data_sz_)) bram
                            , SourceSinkDiff #(Token, Token) ssd_in)
                            (Empty)
                            provisos ( Mul #(rg_sz_, rg_in_data_, data_sz_)
                                     , Add#(b__, TAdd#(TLog#(n_), 1), addr_sz_)
                                     , Add#(c__, rg_sz_, data_sz_)
                                     , Mul#(a__, 8, data_sz_)
                                     , Add#(d__, 8, TMul#(a__, 8)));
    Reg #(Bool) rg_started <- mkReg (False);
    Reg #(Bit #(TAdd #(TLog #(n_), 1))) rg_ctr <- mkReg (0);

    rule rl_start (!rg_started
                   && ssd_in.source.canPeek);
        ssd_in.source.drop;
        rg_started <= True;
        $display("starting bram copy");
    endrule
    rule rl_copy (rg_started
                  && (ssd_in.sink.canPut || !(rg_ctr >= fromInteger (valueOf (n_)))));
        if (rg_ctr >= fromInteger (valueOf (n_))) begin
            //$display("finishing bram copy");
            rg_started <= False;
            ssd_in.sink.put (?);
            rg_ctr <= 0;
        end else begin
            //$display("continuing bram copy");
            Bit #(data_sz_) to_write = 0;
            // data written needs to be reversed so that it is in the right order
            // in the BRAMs
            // the first byte of the hash should be in the lowest byte of BRAM
            for (Integer i = 0; i < valueOf (rg_in_data_); i = i+1) begin
                to_write = to_write | (zeroExtend (v_rg_data[rg_ctr + fromInteger (i)]) << (valueOf (rg_sz_) * (valueOf (rg_in_data_) - i - 1)));
            end
            bram.put (True, zeroExtend (rg_ctr >> log2 (valueOf (rg_in_data_))), fn_rev_byte_order (to_write));
            rg_ctr <= rg_ctr + fromInteger (valueOf (rg_in_data_));
        end
    endrule
endmodule

interface Multi_Push_Stack_IFC #(type data_, numeric type n_push_);
    interface Vector #(n_push_, Sink #(data_)) put_port;
    interface Source #(data_) pop_port;
    method Action print_state;
    method Action reset;
endinterface

// This module DOES NOT CHECK that what you are doing makes sense, and just
// assumes that it makes sense
// put_port[n_push-1] gets popped first
module mkMulti_Push_Stack #(parameter data_ init)
                           (Multi_Push_Stack_IFC #(data_, n_push))
                           provisos (Bits #(data_, data_sz_)
                                    , Add#(a__, TLog#(n_push), TLog#(TAdd#(n_push, 1)))
                                    , FShow #(data_));
    Vector #(n_push, Reg #(data_)) v_rg <- replicateM (mkReg(init));
    Reg #(Bit #(TLog #(TAdd #(n_push, 1)))) rg_ctr <- mkReg (1);
    Wire #(Bool) dw_popped <- mkDWire (False);
    Vector #(n_push, RWire #(data_)) v_rw_pushes <- replicateM (mkRWire);

    Vector #(n_push, Sink #(data_)) v_sinks = newVector;
    for (Integer i = 0; i < valueOf (n_push); i = i+1) begin
        v_sinks[i] = (interface Sink
                          // TODO
                          method Bool canPut = True;
                          method Action put (data_ data);
                              v_rw_pushes[i].wset (data);
                          endmethod
                      endinterface);
    end

    rule rl_always;
        Vector #(n_push, data_) to_write = readVReg (v_rg);
        Bit #(TLog #(TAdd #(n_push, 1))) start = rg_ctr;
        if (dw_popped) begin
            start = start - 1;
        end
        for (Integer i = 0; i < valueOf (n_push); i = i+1) begin
            if (isValid (v_rw_pushes[i].wget)) begin
                Bit #(TLog #(n_push)) idx = truncate (start);
                to_write[idx] = v_rw_pushes[i].wget.Valid;
                start = start + 1;
            end
        end
        for (Integer i = 0; i < valueOf (n_push); i = i+1) begin
            v_rg[i] <= to_write[i];
        end
        rg_ctr <= start;
    endrule

    interface Source pop_port;
        method Bool canPeek = rg_ctr > 0;
        method data_ peek = v_rg[rg_ctr-1];
        method Action drop;
            dw_popped <= True;
        endmethod
    endinterface

    interface put_port = v_sinks;

    method Action reset;
        rg_ctr <= 1;
        for (Integer i = 0; i < valueOf (n_push); i = i+1) begin
            v_rg[i] <= init;
        end
    endmethod

    method Action print_state;
        $display ( "    Multi_Push_Stack state -"
                 , "  rg_ctr: ", fshow (rg_ctr)
                 , "  v_rg: ", fshow (readVReg (v_rg)));
    endmethod
endmodule

function Bit #(n_) fn_truncate_or_ze (Bit #(p_) val);
    Bit #(TAdd #(n_, p_)) extended = zeroExtend (val);
    return truncate (extended);
endfunction

function AXI4_Master #(id_, addr_, data_,
                       awuser_o_, wuser_, buser_,
                       aruser_o_, ruser_) fn_extend_ar_aw_user_fields (AXI4_Master #(id_, addr_, data_,
                                                                                     awuser_i_, wuser_, buser_,
                                                                                     aruser_i_, ruser_) m,
                                                                       Bit #(n_) val)
   provisos ( Add #(n_, awuser_i_, awuser_o_)
            , Add #(n_, aruser_i_, aruser_o_));
   return interface AXI4_Master;
      interface Source aw;
         method drop = m.aw.drop;
         method canPeek = m.aw.canPeek;
         method peek;
            let x = m.aw.peek;
            return AXI4_AWFlit { awid:     x.awid
                               , awaddr:   x.awaddr
                               , awlen:    x.awlen
                               , awsize:   x.awsize
                               , awburst:  x.awburst
                               , awlock:   x.awlock
                               , awcache:  x.awcache
                               , awprot:   x.awprot
                               , awqos:    x.awqos
                               , awregion: x.awregion
                               , awuser:   {val, x.awuser}};
         endmethod
      endinterface
      interface Source w = m.w;
      interface Sink b = m.b;
      interface Source ar;
         method drop = m.ar.drop;
         method canPeek = m.ar.canPeek;
         method peek;
            let x = m.ar.peek;
            return AXI4_ARFlit { arid:     x.arid
                               , araddr:   x.araddr
                               , arlen:    x.arlen
                               , arsize:   x.arsize
                               , arburst:  x.arburst
                               , arlock:   x.arlock
                               , arcache:  x.arcache
                               , arprot:   x.arprot
                               , arqos:    x.arqos
                               , arregion: x.arregion
                               , aruser:   {val, x.aruser}};
         endmethod
      endinterface
      interface Sink r = m.r;
   endinterface;
endfunction


// Utility interface which contains a sink of one type and a source of another
// Used for communication between components
// (i.e. the "client" component will have a sink of requests and a source of responses,
//  and the corresponding "server" will have a source of requests and a sink of responses)
interface SourceSinkDiff #(type a, type b);
  interface Source #(a) source;
  interface Sink #(b) sink;
endinterface

instance Connectable #(SourceSinkDiff #(a, b), SourceSinkDiff #(b, a)) provisos (Bits #(a, a_sz_), Bits #(b, b_sz_));
  module mkConnection #(SourceSinkDiff #(a, b) in1, SourceSinkDiff #(b, a) in2) (Empty);
    mkConnection(in1.source, in2.sink);
    mkConnection(in2.source, in1.sink);
  endmodule
endinstance


endpackage
