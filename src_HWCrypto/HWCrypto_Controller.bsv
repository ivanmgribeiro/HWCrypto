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

package HWCrypto_Controller;

import HWCrypto_Types :: *;
import HWCrypto_Utils :: *;
import RWire :: *;
import SourceSink :: *;

`ifdef HWCRYPTO_CHERI
import CHERICap :: *;
`endif

typedef enum {
    IDLE,
    REQ_KEY_SHORT,
    REQ_KEY_LONG,
    WAIT_READ,
    WAIT_KEY_SHORT,
    WAIT_KEY_LONG,
    HASH_KEY_REQ,
    REQ_DATA,
    WAIT_DATA,
    REQ_HASH,
    WAIT_HASH,
    START_INNER_HASH,
    CONTINUE_INNER_HASH,
    CONTINUE_WITH_DATA,
    COPY_HASH,
    WAIT_COPY_HASH,
    OUTER_HASH,
    WRITE_BACK,
    WAIT_WRITE_BACK,
    FINISH
} State deriving (Bits, Eq, FShow);

interface HWCrypto_Controller_IFC #(numeric type n_brams_);
    (* always_ready *)
    method Bit #(TLog #(n_brams_)) bram_index;

`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
    (* always_ready *)
    method HWCrypto_Ptr cur_cap;
`endif
`endif

    method Action set_verbosity (Bit #(4) new_verb);
endinterface

/*
 * This module contains the finite state machine that controls the rest of the
 * rest of the operations of the engine.
 *
 * It interfaces with the other components using "SourceSinkDiff"s.
 * These contain Sources of requests and Sinks of responses.
 * The direction of the requests and responses depends on the relationship
 * between the controller and the other component; for example the controller
 * receives requests from the register handler module and sends responses
 * back to it, but sends requests to the data mover and receives responses from
 * it.
 *
 * When only control flow is required (i.e. there is no actual request/response
 * information) a Token is used as the request/response type
 * A non-empty Source indicates a request needs to be serviced, and a non-full
 * Sink indicates a response can be received
 *
 * The FSM is implemented by having mutually exclusive rules that fire only in
 * the appropriate state.
 *
 * The module makes use of a "multi-push stack" to track the sequence of states.
 * This is a stack (LIFO) which allows multiple pushes in a cycle, allowing
 * for function-call-like behaviour.
 *
 * Execution is triggered from outside by enqueueing into the src_reg_trigger
 * Source
 */
module mkHWCrypto_Controller #( SourceSinkDiff #(Token, HWCrypto_Err) ssd_regs

                              , SourceSinkDiff #(HWCrypto_Err, Data_Mover_Req #(m_addr_, bram_addr_sz_)) ssd_data_mover

                              , SourceSinkDiff #(Token, SHA256_Req #(bram_addr_sz_)) ssd_sha256

                              , SourceSinkDiff #(Token, Token) ssd_hash_copy

                              , Sink #(Tuple2 #(Bool, Bit #(key_pad_start_sz_))) snk_key_pad_ctrl

                              , Sink #(Bit #(bram_data_sz_)) snk_key_xor_ctrl

                              , HWCrypto_Regs regs)
                              (HWCrypto_Controller_IFC #(n_brams_))
                              provisos ( Add#(0, 64, m_addr_)
                                       , Add#(a__, TAdd#(bram_addr_sz_, TLog#(TDiv#(bram_data_sz_, 8))), 64)
                                       , Mul#(b__, 8, bram_data_sz_)
                                       , Add#(c__, 8, TMul#(b__, 8))
                                       , NumAlias #(key_pad_start_sz_, TAdd #(bram_addr_sz_, TLog #(TDiv #(bram_data_sz_, 8))))
                                       );

    Multi_Push_Stack_IFC #(State, 3) stack_state <- mkMulti_Push_Stack (IDLE);
    rule rl_debug_stack_state;
        if (!stack_state.pop_port.canPeek) begin
            $display ("HWCrypto Controller ERROR: SOMETHING HAS GONE VERY WRONG");
            $display ("    RAN OUT OF STATES IN THE STACK");
        end
    endrule
    Reg #(Bit #(64)) rg_cycle_counter <- mkReg (0);
    Reg #(Bool)      rg_cycle_counter_incr <- mkReg (False);

    Reg #(State) rg_state <- mkReg (IDLE);
    Reg #(State) rg_state_next <- mkRegU;
    Reg #(Bit #(8)) rg_replicate_byte <- mkRegU;
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    Reg #(Bit #(64)) rg_hash_chunk_ctr <- mkReg (0);
    Reg #(Bit #(TLog #(n_brams_))) rg_bram_index <- mkReg (0);
    Reg #(Bit #(TLog #(n_brams_))) rg_bram_index_next <- mkReg (0);

    Reg #(Bit #(64)) rg_chunks_done <- mkRegU;
    Reg #(Bit #(64)) rg_data_chunks_read <- mkRegU;
    Reg #(Bit #(64)) rg_chunks_total <- mkRegU;
    Reg #(Bit #(TAdd #(TLog #(64), 1))) rg_chunk_len <- mkRegU;
    Reg #(Bit #(64)) rg_hash_total_len <- mkRegU;
    Reg #(Bool) rg_chunk_is_first <- mkRegU;
    Reg #(Bool) rg_chunk_is_last <- mkRegU;
    Reg #(Bool) rg_chunk_pad_one <- mkRegU;

    Reg #(Bit #(64)) rg_hash_ptr <- mkRegU;

`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
    // 0: data_ptr, 1: key_ptr, 2: dest_ptr
    Reg #(Bit #(2)) rg_cap_sel <- mkRegU;
`endif
`endif

    function Bit #(TMul #(n_, 8)) fn_replicate_byte (Bit #(8) value)
        provisos (Add#(z__, 8, TMul#(n_, 8)));
        Bit #(TMul #(n_, 8)) res = 0;
        for (Integer i = 0; i < valueOf (n_); i = i+1) begin
            res[i*8 + 7:i*8] = value;
        end
        return res;
    endfunction

    rule rl_count (rg_cycle_counter_incr);
        rg_cycle_counter <= rg_cycle_counter + 1;
    endrule

    rule rl_handle_reg_trigger (stack_state.pop_port.canPeek
                                && stack_state.pop_port.peek == IDLE
                                && ssd_regs.source.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_handle_reg_trigger");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        // keys longer than 64 bytes (block size) need to be hashed
        if (regs.key_len > 64) begin
            if (rg_verbosity > 0) begin
                $display ("    going to REQ_KEY_LONG");
            end
            stack_state.pop_port.drop;
            stack_state.put_port[0].put (REQ_KEY_LONG);
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    going to REQ_KEY_SHORT");
            end
            stack_state.pop_port.drop;
            stack_state.put_port[0].put (REQ_KEY_SHORT);
        end
        rg_bram_index <= 0;
        rg_bram_index_next <= 0;
        rg_chunks_done <= 0;
        rg_cycle_counter <= 0;
        rg_cycle_counter_incr <= True;
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
        // we're going to start fetching the key, so select the key pointer capability
        rg_cap_sel <= 1;
`endif
`endif
    endrule

    rule rl_req_key_short (stack_state.pop_port.canPeek
                           && stack_state.pop_port.peek == REQ_KEY_SHORT
                           && ssd_data_mover.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_key_short");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  :
`ifdef HWCRYPTO_CHERI
                                           getAddr (regs.key_ptr)
`else
                                           regs.key_ptr
`endif
                             , bram_addr : 0
                             , dir       : BUS2BRAM
                             , len       : regs.key_len};
        ssd_data_mover.sink.put (dm_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_KEY_SHORT);
        if (rg_verbosity > 0) begin
            $display ("    dm_req: ", fshow (dm_req));
            $display ("    going to WAIT_KEY_SHORT");
        end
    endrule

    rule rl_wait_key_short (stack_state.pop_port.canPeek
                            && stack_state.pop_port.peek == WAIT_KEY_SHORT
                            && ssd_data_mover.source.canPeek
                            && ssd_data_mover.source.peek == OKAY
                            && snk_key_pad_ctrl.canPut
                            && snk_key_xor_ctrl.canPut
                            );
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_key_short");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_data_mover.source.drop;
        // now need to prep key
        // skip this for now and get data + hash it
        // TODO might reuse this rule after hashing long keys
        if (regs.key_len < 64) begin
            snk_key_pad_ctrl.put (tuple2 (True, truncate (regs.key_len)));
        end else if (regs.key_len == 64) begin
            snk_key_pad_ctrl.put (tuple2 (False, ?));
        end else begin
            // if the key was bigger than 64 bytes, then we will have hashed it
            // down to a 32 byte key
            snk_key_pad_ctrl.put (tuple2 (True, 32));
        end

        snk_key_xor_ctrl.put (fn_replicate_byte ('h36));
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (START_INNER_HASH);
    endrule

    rule rl_req_key_long (stack_state.pop_port.canPeek
                          && stack_state.pop_port.peek == REQ_KEY_LONG
                          && snk_key_pad_ctrl.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_key_long");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        rg_hash_total_len <= regs.key_len;
        rg_hash_ptr <=
`ifdef HWCRYPTO_CHERI
                       getAddr (regs.key_ptr);
`else
                       regs.key_ptr;
`endif
        rg_chunks_done <= 0;
        rg_data_chunks_read <= 0;
        Bit #(TLog #(64)) len_bottom_bits = truncate (regs.key_len);
        let last_over_55 = len_bottom_bits > 55;
        rg_chunks_total <= (regs.key_len >> (log2 (64))) + (last_over_55 ? 2 : 1);

        if (rg_verbosity > 0) begin
            $display ( "    total_len: ", fshow (regs.key_len)
                     , "  len_bottom_bits: ", fshow (len_bottom_bits));
        end
        snk_key_pad_ctrl.put (tuple2 (False, ?));

        stack_state.pop_port.drop;
        stack_state.put_port[2].put (CONTINUE_WITH_DATA);
        stack_state.put_port[1].put (COPY_HASH);
        stack_state.put_port[0].put (WAIT_KEY_LONG);
    endrule

    rule rl_wait_req_key_long (stack_state.pop_port.canPeek
                               && stack_state.pop_port.peek == WAIT_KEY_LONG
                               && snk_key_pad_ctrl.canPut
                               && snk_key_xor_ctrl.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_req_key_long");
            $display ("    cycle count: ", fshow (rg_cycle_counter));
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        snk_key_pad_ctrl.put (tuple2 (True, 32));
        snk_key_xor_ctrl.put (fn_replicate_byte ('h36));
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (START_INNER_HASH);
    endrule

    rule rl_hash_key_req (stack_state.pop_port.canPeek
                          && stack_state.pop_port.peek == HASH_KEY_REQ
                          && ssd_sha256.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_hash_key_req");
            $display ("    cycle count: ", fshow (rg_cycle_counter));
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : truncate (regs.key_len)
                         , reset_hash : True
                         // TODO change this
                         , pad_one    : True
                         , append_len : True};
        ssd_sha256.sink.put (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule


    // start the inner hash by hashing what is in the key bram
    rule rl_start_inner_hash (stack_state.pop_port.canPeek
                              && stack_state.pop_port.peek == START_INNER_HASH
                              && ssd_sha256.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_start_inner_hash");
            $display ("    cycle count: ", fshow (rg_cycle_counter));
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : 64
                         , reset_hash : True
                         , pad_one    : False
                         , append_len : False};
        ssd_sha256.sink.put (sha_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (CONTINUE_INNER_HASH);
    endrule

    // set up for fetching data from memory to the data bram and hashing it
    rule rl_continue_inner_hash (stack_state.pop_port.canPeek
                                 && stack_state.pop_port.peek == CONTINUE_INNER_HASH
                                 && ssd_sha256.source.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_continue_inner_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_sha256.source.drop;

        rg_bram_index <= 1;
        stack_state.pop_port.drop;
        stack_state.put_port[2].put (CONTINUE_WITH_DATA);
        stack_state.put_port[1].put (COPY_HASH);
        stack_state.put_port[0].put (OUTER_HASH);
        rg_bram_index_next <= 0;
        rg_replicate_byte <= 'h5c;
        let total_len = regs.data_len + 64;
        rg_hash_total_len <= total_len;
        rg_hash_ptr <=
`ifdef HWCRYPTO_CHERI
                       getAddr (regs.data_ptr);
`else
                       regs.data_ptr;
`endif
        rg_chunks_done <= 1;
        rg_data_chunks_read <= 0;

        Bit #(TLog #(64)) len_bottom_bits = truncate (regs.data_len);
        let last_over_55 = len_bottom_bits > 55;
        //let last_is_64 = reduceOr (len_bottom_bits) == 1'b0;
        //let need_extra_chunk = last_over_55 || last_is_64;
        //rg_chunks_need_empty_chunk <= last_over_55;

        // if the last chunk is more than 55 bytes long we will need an extra
        // chunk which is empty apart from 0s and the length and possibly a
        // 1 at the start
        rg_chunks_total <= (regs.data_len >> (log2 (64))) + (last_over_55 ? 3 : 2);
        if (rg_verbosity > 0) begin
            $display ( "    total_len: ", fshow (total_len)
                     , "  len_bottom_bits: ", fshow (len_bottom_bits)
                     , "  last_over_55: ", fshow (last_over_55));
        end
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
        // we're going to start fetching data, so select the data capability
        rg_cap_sel <= 0;
`endif
`endif
    endrule

    // continue the inner hash by fetching data and hashing it
    rule rl_continue_hash_with_data (stack_state.pop_port.canPeek
                                     && stack_state.pop_port.peek == CONTINUE_WITH_DATA
                                     && ssd_data_mover.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_continue_hash_with_data");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        // find the number of 64byte chunks that we will need
        Bit #(TLog #(64)) len_bottom_bits = truncate (rg_hash_total_len);
        Bit #(1) bottom_or = reduceOr (len_bottom_bits);
        Bool last_is_64 = bottom_or == 1'b0;
        Bool last_over_55 = len_bottom_bits > 55;
        let num_chunks = rg_chunks_total;
        if (rg_verbosity > 0) begin
            $display ( "    num_chunks: ", fshow (num_chunks)
                     , "  rg_chunks_done: ", fshow (rg_chunks_done)
                     , "  rg_data_chunks_read: ", fshow (rg_data_chunks_read)
                     , "  last_is_64: ", fshow (last_is_64));
        end

        if (rg_chunks_done == num_chunks) begin
            stack_state.pop_port.drop;
            if (rg_verbosity > 0) begin
                $display ("%m HWCrypto Controller data hash finished");
            end
        end else begin
            let is_last = rg_chunks_done == num_chunks - 1;
            let is_second_last = rg_chunks_done == num_chunks - 2;
            // request the next chunk from memory and hash it
            let requested = False;
            let len = 0;
            if (!is_last || (!last_over_55 && !last_is_64)) begin
                len = is_last && !last_over_55 ? zeroExtend (len_bottom_bits)
                    : is_last &&  last_over_55 ? 0
                    : is_second_last &&  last_over_55 ? zeroExtend (len_bottom_bits)
                    : 64;
                Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
                    = Data_Mover_Req { bus_addr  : rg_hash_ptr + (rg_data_chunks_read << log2 (64))
                                     , bram_addr : 0
                                     , dir       : BUS2BRAM
                                     , len       : len};
                ssd_data_mover.sink.put (dm_req);
                if (rg_verbosity > 0) begin
                    $display ("    dm_req: ", fshow (dm_req));
                    $display ("    going to WAIT_DATA");
                end
                requested = True;
            end
            // TODO
            stack_state.pop_port.drop;
            stack_state.put_port[0].put (requested ? WAIT_READ : REQ_HASH);
            rg_chunk_len <= len;
            rg_chunk_is_last <= is_last;
            rg_chunk_pad_one <= (is_last && !last_over_55)
                                 || (is_second_last && last_over_55);
            rg_chunk_is_first <= rg_chunks_done == 0;
            rg_data_chunks_read <= rg_data_chunks_read + 1;
        end
    endrule


    rule rl_wait_read (stack_state.pop_port.canPeek
                       && stack_state.pop_port.peek == WAIT_READ
                       && ssd_data_mover.source.canPeek
                       && ssd_data_mover.source.peek == OKAY
                       && ssd_sha256.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_read");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_data_mover.source.drop;
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : zeroExtend (rg_chunk_len)
                         , reset_hash : rg_chunk_is_first
                         , pad_one    : rg_chunk_pad_one
                         , append_len : rg_chunk_is_last};
        ssd_sha256.sink.put (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end

        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_req_hash (stack_state.pop_port.canPeek
                      && stack_state.pop_port.peek == REQ_HASH
                      && ssd_sha256.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : zeroExtend (rg_chunk_len)
                         , reset_hash : rg_chunk_is_first
                         , pad_one    : rg_chunk_pad_one
                         , append_len : rg_chunk_is_last};
        ssd_sha256.sink.put (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end

        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_wait_hash (stack_state.pop_port.canPeek
                       && stack_state.pop_port.peek == WAIT_HASH
                       && ssd_sha256.source.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_sha256.source.drop;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (CONTINUE_WITH_DATA);
        rg_chunks_done <= rg_chunks_done + 1;
    endrule

    rule rl_wait_data (stack_state.pop_port.canPeek
                       && stack_state.pop_port.peek == WAIT_DATA
                       && ssd_data_mover.source.canPeek
                       && ssd_data_mover.source.peek == OKAY);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_data");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_data_mover.source.drop;

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : truncate (regs.data_len)
                         , reset_hash : True
                         , pad_one    : True
                         , append_len : True};
        ssd_sha256.sink.put (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_copy_hash_to_data_bram (stack_state.pop_port.canPeek
                                    && stack_state.pop_port.peek == COPY_HASH
                                    && ssd_hash_copy.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_copy_hash_to_data_bram");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_hash_copy.sink.put (?);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_COPY_HASH);
    endrule

    Reg #(Bool) rg_key_hash_req <- mkRegU;
    Reg #(Bool) rg_key_hash_done <- mkRegU;
    Reg #(Bool) rg_data_hash_done <- mkRegU;
    rule rl_wait_copy_hash (stack_state.pop_port.canPeek
                            && stack_state.pop_port.peek == WAIT_COPY_HASH
                            && ssd_hash_copy.source.canPeek
                            && snk_key_xor_ctrl.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_copy_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_hash_copy.source.drop;
        rg_bram_index <= rg_bram_index_next;
        rg_key_hash_req <= False;
        rg_key_hash_done <= False;
        rg_data_hash_done <= False;
        snk_key_xor_ctrl.put (fn_replicate_byte (rg_replicate_byte));
        stack_state.pop_port.drop;
    endrule

    rule rl_outer_hash (stack_state.pop_port.canPeek
                        && stack_state.pop_port.peek == OUTER_HASH
                        );
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_outer_hash");
            $display ("    rg_key_hash_req: ", fshow (rg_key_hash_req));
            $display ("    rg_key_hash_done: ", fshow (rg_key_hash_done));
            $display ("    rg_data_hash_done: ", fshow (rg_data_hash_done));
            $display ("    cycle counter value: ", fshow (rg_cycle_counter));
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        if (!rg_key_hash_req) begin
            $display ("    case 1");
            rg_key_hash_req <= True;
            SHA256_Req #(bram_addr_sz_) sha_req
                = SHA256_Req { bram_addr  : 0
                             , len        : 64
                             , reset_hash : True
                             , pad_one    : False
                             , append_len : False};
            ssd_sha256.sink.put (sha_req);
        end else if (rg_key_hash_req && !rg_key_hash_done && ssd_sha256.source.canPeek) begin
            $display ("    case 2");
            rg_bram_index <= 1;
            rg_key_hash_done <= True;
        end else if (rg_key_hash_done && !rg_data_hash_done && ssd_sha256.source.canPeek) begin
            $display ("    case 3");
            ssd_sha256.source.drop;
            rg_data_hash_done <= True;
            SHA256_Req #(bram_addr_sz_) sha_req
                = SHA256_Req { bram_addr  : 0
                             , len        : 32
                             , reset_hash : False
                             , pad_one    : True
                             , append_len : True};
            ssd_sha256.sink.put (sha_req);
        end else if (rg_key_hash_done && rg_data_hash_done && ssd_sha256.source.canPeek) begin
            $display ("    case 4");
            ssd_sha256.source.drop;
            rg_replicate_byte <= 0;
            rg_bram_index_next <= 1;
            stack_state.pop_port.drop;
            stack_state.put_port[1].put (COPY_HASH);
            stack_state.put_port[0].put (WRITE_BACK);
        end
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
        // we've finished reading the data and are not hashing it, so select the
        // destination capability to write back to memory
        rg_cap_sel <= 2;
`endif
`endif
    endrule

    rule rl_write_back_to_mem (stack_state.pop_port.canPeek
                               && stack_state.pop_port.peek == WRITE_BACK
                               && ssd_data_mover.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_write_back_to_mem");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  :
`ifdef HWCRYPTO_CHERI
                                           getAddr (regs.dest_ptr)
`else
                                           regs.dest_ptr
`endif
                             , bram_addr : 0
                             , dir       : BRAM2BUS
                             , len       : 32};
        ssd_data_mover.sink.put (dm_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_WRITE_BACK);
    endrule

    rule rl_wait_write_back (stack_state.pop_port.canPeek
                             && stack_state.pop_port.peek == WAIT_WRITE_BACK
                             && ssd_data_mover.source.canPeek
                             && ssd_data_mover.source.peek == OKAY);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_write_back");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        ssd_data_mover.source.drop;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (FINISH);
    endrule

    // ASSERT: ssd_regs.source.canPeek MUST be true at this point since to get into this state we must
    //         it must have been true before and only the finish/error states drop from it and these go back
    //         to the idle state which waits for canPeek to be true
    rule rl_finish (stack_state.pop_port.canPeek
                    && stack_state.pop_port.peek == FINISH
                    //&& ssd_regs.source.canPeek // redundant, see ASSERT above
                    && ssd_regs.sink.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_finish");
            $display ("    cycles counted: ", fshow (rg_cycle_counter));
        end
        ssd_regs.source.drop;
        ssd_regs.sink.put(OKAY);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (IDLE);
    endrule

    //rule rl_debug_dm (ssd_data_mover.source.canPeek);
    //    $display("%m HWCrypto Controller rl_debug_dm");
    //    $display("ssd_data_mover.source.peek: ", fshow(ssd_data_mover.source.peek));
    //    stack_state.print_state;
    //endrule
    // ASSERT: ssd_regs.source.canPeek MUST be true at this point since to get into this state we must
    //         it must have been true before and only the finish/error states drop from it and these go back
    //         to the idle state which waits for canPeek to be true
    rule rl_handle_dm_err (stack_state.pop_port.canPeek
                           && (stack_state.pop_port.peek == WAIT_WRITE_BACK
                               || stack_state.pop_port.peek == WAIT_KEY_SHORT
                               || stack_state.pop_port.peek == WAIT_READ
                               || stack_state.pop_port.peek == WAIT_DATA)
                           && ssd_data_mover.source.canPeek
                           && ssd_data_mover.source.peek != OKAY
                           // && ssd_regs.source.canPeek // redundant, see ASSERT above
                           );
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_handle_dm_err");
        end
        // The datamover encountered a bus error; reset the state, write error
        // to registers and go to IDLE
        stack_state.reset;
        ssd_regs.source.drop;
        ssd_data_mover.source.drop;
        if (ssd_regs.sink.canPut) begin
            ssd_regs.sink.put (ssd_data_mover.source.peek);
            if (rg_verbosity > 0) begin
                $display ("    sending error ", fshow (ssd_data_mover.source.peek), " to ssd_regs.sink");
            end
        end else begin
            $display ("    ERROR: not able to push result to register handler");
        end
    endrule


    method bram_index = rg_bram_index;

`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
    method cur_cap = rg_cap_sel == 0 ? regs.data_ptr
                   : rg_cap_sel == 1 ? regs.key_ptr
                   : regs.dest_ptr;
`endif
`endif

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod
endmodule




endpackage
