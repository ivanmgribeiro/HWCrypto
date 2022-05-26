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

package HWCrypto_Reg_Handler;

import HWCrypto_Types :: *;
import HWCrypto_Utils :: *;
import AXI :: *;
import SourceSink :: *;

`ifdef HWCRYPTO_CHERI
import CHERICap :: *;
import CHERICC_Fat :: *;
`endif

`define SPARAMS s_id_, s_addr_, s_data_, s_awuser_, s_wuser_, s_buser_, s_aruser_, s_ruser_

`ifdef HWCRYPTO_CHERI

`else
typedef Bit #(64) Pointer_Type;
typedef Bit #(64) Len_Type;
`endif

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
 *   +  TODO need to reason about what happens when reads and writes are
 *      received in the same cycle. the use of the rg_flits_handled register
 *      will not allow the rules to fire in the same cycle
 *
 *  Interface:
 *   +  If the Sink that is passed as an argument can be enqueued into,
 *      then the HWCrypto is idle. Otherwise it is not.
 *
 *  two options for handling capabilities:
 *   + do the checking here when we attempt to trigger a transfer, and don't
 *     don't trigger when we see an error
 *   + do the checking in a shim between this and the bus, and signal here
 *     when the datamover gets a bus error
 *
 *  bus-accessible register mapping:
 *   + for now, only handle properly sized accesses
 *   + we only use the bottom 7 bits of the address
 */
// TODO remove restriction for addr and data to be 64b
module mkHWCrypto_Reg_Handler #(Sink #(Token) snk, Source #(HWCrypto_Err) src)
                               (HWCrypto_Reg_Handler_IFC #(`SPARAMS))
                               provisos ( Add #(0, 64, s_addr_)
                                        , Add #(0, 64, s_data_)
                                        );
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);

    AXI4_Shim #(`SPARAMS) shim <- mkAXI4ShimFF;

    Integer dest_len = 32;

`ifdef HWCRYPTO_CHERI
    let data_ptr_idx = 0;
    let key_ptr_idx = 2;
    let dest_ptr_idx = 4;
    let data_len_idx = 6;
    let key_len_idx = 7;
    let status_idx = 8;
`else
    let data_ptr_idx = 0;
    let key_ptr_idx = 1;
    let dest_ptr_idx = 2;
    let data_len_idx = 3;
    let key_len_idx = 4;
    let status_idx = 5;
`endif

    Reg #(HWCrypto_Ptr) rg_data_ptr <- mkRegU;
    Reg #(HWCrypto_Ptr) rg_key_ptr  <- mkRegU;
    Reg #(HWCrypto_Ptr) rg_dest_ptr <- mkRegU;
    Reg #(HWCrypto_Len) rg_data_len <- mkRegU;
    Reg #(HWCrypto_Len) rg_key_len  <- mkRegU;

    Reg #(Bit #(s_data_))  rg_prev_flit_data <- mkRegU;
    Reg #(Bit #(s_wuser_)) rg_prev_flit_wuser <- mkRegU;
    Reg #(Bit #(s_ruser_)) rg_prev_flit_ruser <- mkRegU;

    Reg #(AXI4_Len) rg_flits_handled <- mkReg (0);
    // bsc seems bad at optimising this kind of thing
    let rg_flits_incr = rg_flits_handled + 1;

    Reg #(Bool) rg_read_ok <- mkReg (True);

`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_INT_CHECK
    Reg #(Bool) rg_do_check <- mkReg (False);
    Reg #(Bool) rg_cheri_err <- mkReg (False);
`ifndef HWCRYPTO_CHERI_FAT
    Reg #(Bit #(2)) rg_check_ctr <- mkReg (0);
    Reg #(Bool) rg_check_ok <- mkReg (True);
`endif // !HWCRYPTO_CHERI_FAT
`endif // HWCRYPTO_CHERI_INT_CHECK
`endif // HWCRYPTO_CHERI

    rule rl_handle_write (shim.master.aw.canPeek
                          && shim.master.w.canPeek
                          && shim.master.b.canPut);
        let awflit = shim.master.aw.peek;
        let wflit = shim.master.w.peek;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto: received write request");
            $display ("    awflit: ", fshow (awflit));
            $display ("    wflit: ", fshow (wflit));
        end

        // TODO make this more general
        // TODO handle 64b caps
        // extract only the bottom bits of the address
        Bit #(7) addr_int = truncate (awflit.awaddr);
        let index = awflit.awaddr[6:3];

        // TODO check range
`ifdef HWCRYPTO_CHERI
        let is_cap_addr = addr_int < 'h30;
        let is_valid_addr = !is_cap_addr && awflit.awaddr[2:0] == 0    // non-capability alignment
                            || is_cap_addr && awflit.awaddr[3:0] == 0; // capability alignment
        let is_valid_size = awflit.awsize == 8; // only allow 64bit flits
        let is_valid_len = !is_cap_addr && awflit.awlen == 0
                           || is_cap_addr && awflit.awlen == 1; // capability writes must be 2*64b flits
`else
        let is_valid_addr = awflit.awaddr[2:0] == 0;
        let is_valid_size = awflit.awsize == 8;
        let is_valid_len = awflit.awlen == 0;
`endif

        if (is_valid_addr && is_valid_size && is_valid_len) begin
            if (rg_verbosity > 0) begin
                $display ("    request is valid");
            end
            if (rg_flits_handled != awflit.awlen) begin
`ifndef HWCRYPTO_CHERI
                $display ("%m HWCrypto_Reg_Handler rl_handle_write WARNING: multi-flit writes should not happen with no CHERI support!");
`endif
                // this is a multi-flit request and this is not the final flit
                // register this flit's data and wait for the next flit
                rg_prev_flit_data <= wflit.wdata;
                rg_prev_flit_wuser <= wflit.wuser;
                rg_flits_handled <= rg_flits_incr;
                // keep the aw flit for next cycle
            end else begin
                if (wflit.wlast != True) begin
                    $display ("%m HWCrypto_Reg_Handler rl_handle_write WARNING: wlast is true but this is not the last expected flit!");
                end

                // only allow writes when we are not currently processing a request
                if (snk.canPut
`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_INT_CHECK
                               && !rg_do_check
`endif
`endif
                                              ) begin
                    if (rg_verbosity > 0) begin
                        $display ("    HWCrypto is idle; writing to register with index ", fshow (index));
                        $display ("        value to write: ", fshow (wflit.wdata));
                    end
`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_FAT
                    // with HWCRYPTO_CHERI, with HWCRYPTO_CHERI_FAT
                    Bit #(1) valid_bit = fn_truncate_or_ze (wflit.wuser & rg_prev_flit_wuser);
                    CapMem cap_mem = { valid_bit
                                     , wflit.wdata
                                     , rg_prev_flit_data};
                    Bit #(129) t1 = 'ha1234;
                    CapMem test = t1;
                    CapReg cap_exp = fromMem (unpack (cap_mem));
                    if (rg_verbosity > 0) begin
                        $display ("    expanded capability ", fshow (cap_mem), " into ", fshow (cap_exp));
                    end
                    if (index == data_ptr_idx)      rg_data_ptr <= cap_exp;
                    else if (index == key_ptr_idx)  rg_key_ptr  <= cap_exp;
                    else if (index == dest_ptr_idx) rg_dest_ptr <= cap_exp;
`else
                    // with HWCRYPTO_CHERI, without HWCRYPTO_CHERI_FAT
                    CapMem cap_mem = unpack ({ fn_truncate_or_ze (wflit.wuser & rg_prev_flit_wuser)
                                             , wflit.wdata
                                             , rg_prev_flit_data});
                    if (index == data_ptr_idx)      rg_data_ptr <= cap_mem;
                    else if (index == key_ptr_idx)  rg_key_ptr  <= cap_mem;
                    else if (index == dest_ptr_idx) rg_dest_ptr <= cap_mem;
`endif
`else
                    // without HWCRYPTO_CHERI
                    if (index == data_ptr_idx)      rg_data_ptr <= wflit.wdata;
                    else if (index == key_ptr_idx)  rg_key_ptr  <= wflit.wdata;
                    else if (index == dest_ptr_idx) rg_dest_ptr <= wflit.wdata;
`endif
                    else if (index == data_len_idx) rg_data_len <= wflit.wdata;
                    else if (index == key_len_idx)  rg_key_len  <= wflit.wdata;
                    else if (index == status_idx) begin
                        let trigger_next = True;
`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_INT_CHECK
                        if (rg_verbosity > 0) begin
                            $display ("    Triggering internal CHERI check");
                        end
                        rg_do_check <= True;
                        rg_cheri_err <= False;
                        trigger_next = False;
`endif
`endif
                        if (trigger_next) begin
                            if (rg_verbosity > 0) begin
                                $display ("    Triggering next stage");
                            end
                            snk.put (?); // trigger next stage
                        end
                        if (src.canPeek) begin
                            src.drop;
                        end
                    end
                end else begin
                    if (rg_verbosity > 0) begin
                        $display ("    HWCrypto is not idle; ignoring write");
                    end
                end

                // we're done with this request - drop the aw flit and issue a response
                shim.master.aw.drop;
                rg_flits_handled <= 0;
                AXI4_BFlit #(s_id_, s_buser_) bflit = AXI4_BFlit { bid: awflit.awid
                                                                  , bresp: OKAY
                                                                  , buser: 0
                                                                  };
                if (rg_verbosity > 1) begin
                    $display ("    response: ", fshow (bflit));
                end
                shim.master.b.put (bflit);
            end
            // always drop the w flit
            shim.master.w.drop;
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
            shim.master.aw.drop;
            shim.master.w.drop;
        end
    endrule

    rule rl_handle_read_1 (shim.master.ar.canPeek
                           && shim.master.r.canPut
                           && rg_flits_handled != shim.master.ar.peek.arlen);
        let arflit = shim.master.ar.peek;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto rl_handle_read_1: received read request");
            $display ("    arflit: ", fshow (arflit));
        end

        // TODO handle 64b caps
        Bit #(7) addr_int = truncate (arflit.araddr);
        let index = arflit.araddr[6:3];
`ifdef HWCRYPTO_CHERI
        let is_cap_addr = addr_int < 'h30;
        let is_valid_addr = !is_cap_addr && arflit.araddr[2:0] == 0    // non-capability alignment
                            || is_cap_addr && arflit.araddr[3:0] == 0; // capability alignment
        let is_valid_size = arflit.arsize == 8; // only allow 64bit flits
        let is_valid_len = !is_cap_addr && arflit.arlen == 0
                           || is_cap_addr && arflit.arlen == 1; // capability writes must be 2*64b flits
`else
        let is_valid_addr = arflit.araddr[2:0] == 0;
        let is_valid_size = arflit.arsize == 8;
        let is_valid_len = arflit.arlen == 0;
`endif

        let is_valid_access = rg_read_ok
                              && is_valid_addr
                              && is_valid_size
                              && is_valid_len;
        if (rg_verbosity > 1) begin
            $display ("    rg_read_ok: ", fshow (is_valid_addr));
            $display ("    is_valid_addr: ", fshow (is_valid_addr));
            $display ("    is_valid_size: ", fshow (is_valid_addr));
            $display ("    is_valid_len: ", fshow (is_valid_addr));
        end

        let data = ?;
        let user = 0;
        if (is_valid_access) begin
            if (rg_verbosity > 0) begin
                $display ("    request is valid");
                $display ("    reading from index ", fshow (index));
            end
`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_FAT
            // with HWCRYPTO_CHERI, with HWCRYPTO_CHERI_FAT
            let cap_fat = index == data_ptr_idx ? rg_data_ptr
                        : index == key_ptr_idx  ? rg_key_ptr
                        : rg_dest_ptr;
            match {.cap_valid, .cap_data} = toMem (cap_fat);

            if (rg_verbosity > 0) begin
                $display ("    compressed capability ", fshow (cap_fat), " into ", fshow (tuple2 (cap_valid, cap_data)));
            end
            data = truncate (cap_data);
            rg_prev_flit_data <= truncateLSB (cap_data);
            rg_prev_flit_ruser <= fn_truncate_or_ze (pack (cap_valid));
`else
            // with HWCRYPTO_CHERI, without HWCRYPTO_CHERI_FAT
            let cap_mem = index == data_ptr_idx ? rg_data_ptr
                        : index == key_ptr_idx  ? rg_key_ptr
                        : rg_dest_ptr;
            Bit #(1) cap_valid = truncateLSB(cap_mem);
            Bit #(TSub #(SizeOf #(CapMem), 1)) cap_data = truncate (cap_mem);
            rg_prev_flit_data <= truncateLSB (cap_data);
            rg_prev_flit_ruser <= fn_truncate_or_ze (cap_valid);
`endif
`else
            // without HWCRYPTO_CHERI
            $display ("%m HWCrypto_Reg_Handler rl_handle_read_1 WARNING: multi-flit reads should not happen with no CHERI support!");
`endif

        end else begin
            if (rg_verbosity > 0) begin
                $display ("    request is invalid");
            end
        end

        AXI4_RFlit #(s_id_, s_data_, s_ruser_) rflit = AXI4_RFlit { rid:   arflit.arid
                                                                  , rdata: data
                                                                  , rresp: is_valid_access ? OKAY : SLVERR
                                                                  , rlast: False
                                                                  , ruser: user
                                                                  };
        rg_read_ok <= is_valid_access;
        rg_flits_handled <= rg_flits_incr;
    endrule

    rule rl_handle_read_2 (shim.master.ar.canPeek
                           && shim.master.r.canPut
                           && rg_flits_handled == shim.master.ar.peek.arlen);
        shim.master.ar.drop;
        let arflit = shim.master.ar.peek;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto: received read request");
            $display ("    arflit: ", fshow (arflit));
        end

        // TODO handle 64b caps
        Bit #(7) addr_int = truncate (arflit.araddr);
`ifdef HWCRYPTO_CHERI
        let is_cap_addr = addr_int < 'h30;
        let is_valid_addr = !is_cap_addr && arflit.araddr[2:0] == 0    // non-capability alignment
                            || is_cap_addr && arflit.araddr[3:0] == 0; // capability alignment
        let is_valid_size = arflit.arsize == 8; // only allow 64bit flits
        let is_valid_len = !is_cap_addr && arflit.arlen == 0
                           || is_cap_addr && arflit.arlen == 1; // capability writes must be 2*64b flits
`else
        let is_valid_addr = arflit.araddr[2:0] == 0;
        let is_valid_size = arflit.arsize == 8;
        let is_valid_len = arflit.arlen == 0;
`endif
        let is_valid_access = rg_read_ok
                              && is_valid_addr
                              && is_valid_size
                              && is_valid_len;

        // TODO make this more general
        let index = arflit.araddr[6:3];
        let data = ?;
        let user = 0;

        if (is_valid_access) begin
            if (rg_verbosity > 0) begin
                $display ("    request is valid");
                $display ("    reading from index ", fshow (index));
            end
            if (rg_flits_handled != 0) begin
`ifdef HWCRYPTO_CHERI
                // return whatever is in the registers
                data = rg_prev_flit_data;
                user = rg_prev_flit_ruser;
`else
                $display ("%m HWCrypto_Reg_Handler rl_handle_read_2 WARNING: multi-flit reads should not happen with no CHERI support!");
`endif
            end else begin
                // this is a single-flit access
                // this is inefficient - we should be able to share the logic
                // that selects (and possibly compresses) the capabilities
                // between this and the previous read rule
                // if we are able to return capabilities in one flit
                // then there is never a case where we would do it in
                // two flits, so we only ever need one instance of toMem
`ifdef HWCRYPTO_CHERI
                if (is_cap_addr) begin
                    $display ("%m HWCrypto_Reg_Handler rl_handle_read_2 WARNING: single-cycle capability access not supported");
                end else begin
                    if (index == data_len_idx) begin
                        data = rg_data_len;
                    end else if (index == key_len_idx) begin
                        data = rg_key_len;
                    end else if (index == status_idx) begin
`ifdef HWCRYPTO_CHERI_INT_CHECK
                        let cheri_err = rg_cheri_err;
                        let is_busy = !snk.canPut && !rg_do_check;
`else
                        let cheri_err = False;
                        let is_busy = !snk.canPut;
`endif
                        data = zeroExtend ({ pack (cheri_err)
                                           , pack (src.canPeek && src.peek != OKAY)
                                           , pack (is_busy)});

                    end
                end
`else
                // without HWCRYPTO_CHERI
                if (index == data_ptr_idx)      data = rg_data_ptr;
                else if (index == key_ptr_idx)  data = rg_data_len;
                else if (index == dest_ptr_idx) data = rg_key_ptr;
                else if (index == data_len_idx) data = rg_key_len;
                else if (index == key_len_idx)  data = rg_dest_ptr;
                else if (index == status_idx)   data = zeroExtend ({ pack (src.canPeek && src.peek != OKAY)
                                                                   , pack (!snk.canPut)});
`endif
            end
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    request is invalid");
`ifdef HWCRYPTO_CHERI
                $display ("        is_cap_addr: ", fshow (is_cap_addr));
`endif
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
        rg_flits_handled <= 0;
        rg_read_ok <= True;
    endrule

`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_INT_CHECK
    rule rl_do_check (rg_do_check);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Reg Handler rl_do_check");
        end
        let caps_ok = False;
        let all_ok = False;
        let final_check = True;
`ifdef HWCRYPTO_CHERI_FAT
        CapPipe cap_data_pipe = cast (rg_data_ptr);
        CapPipe cap_key_pipe = cast (rg_key_ptr);
        CapPipe cap_dest_pipe = cast (rg_dest_ptr);
        if (rg_verbosity > 1) begin
            $display ("    caps:");
            $display ("    data cap: ", fshow (cap_data_pipe));
            $display ("    key cap: ", fshow (cap_key_pipe));
            $display ("    dest cap: ", fshow (cap_dest_pipe));
        end
        // TODO check tag, seal, etc
        caps_ok = (getBase (cap_data_pipe) <= getAddr (cap_data_pipe))                  // data pointer checks
                  && (getTop (cap_data_pipe) >= zeroExtend (getAddr (cap_data_pipe)) + zeroExtend (rg_data_len))
                  && (getHardPerms (cap_data_pipe).permitLoad)
                  && (getBase (cap_key_pipe) <= getAddr (cap_key_pipe))                 // key pointer checks
                  && (getTop (cap_key_pipe) >= zeroExtend (getAddr (cap_key_pipe)) + zeroExtend (rg_key_len))
                  && (getHardPerms (cap_key_pipe).permitLoad)
                  && (getBase (cap_dest_pipe) <= getAddr (cap_dest_pipe))               // dest pointer checks
                  && (getTop (cap_dest_pipe) >= zeroExtend (getAddr (cap_dest_pipe)) + fromInteger (dest_len))
                  && (getHardPerms (cap_dest_pipe).permitStore);
        all_ok = caps_ok;
`else // !HWCRYPTO_CHERI_FAT
        final_check = rg_check_ctr == 2;
        let cap = rg_check_ctr == 0 ? rg_data_ptr
                : rg_check_ctr == 1 ? rg_key_ptr
                : rg_dest_ptr;
        CapPipe cap_pipe = cast (cap);
        let len = rg_check_ctr == 0 ? rg_data_len
                : rg_check_ctr == 1 ? rg_key_len
                : fromInteger (dest_len);
        caps_ok = (getBase (cap_pipe) <= getAddr (cap_pipe))
                  && (getTop (cap_pipe) >= zeroExtend (getAddr (cap_pipe)) + zeroExtend (len))
                  && (rg_check_ctr == 2 ? getHardPerms (cap_pipe).permitStore
                                        : getHardPerms (cap_pipe).permitLoad);
        all_ok = final_check && rg_check_ok && caps_ok;
        if (!final_check) begin
            rg_check_ctr <= rg_check_ctr + 1;
            rg_check_ok <= all_ok;
        end
`endif // HWCRYPTO_CHERI_FAT

        if (final_check) begin
            rg_cheri_err <= !all_ok;
            rg_do_check <= False;

`ifndef HWCRYPTO_CHERI_FAT
            rg_check_ctr <= 0;
            rg_check_ok <= True;
`endif // HWCRYPTO_CHERI_FAT
            if (all_ok) begin
                snk.put (?);
            end
        end
    endrule
`endif // HWCRYPTO_CHERI_INT_CHECK
`endif // HWCRYPTO_CHERI


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
