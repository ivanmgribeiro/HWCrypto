package HWCrypto_Controller;

import HWCrypto_Types :: *;
import HWCrypto_Utils :: *;
import RWire :: *;
import SourceSink :: *;

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

interface HWCrypto_Controller_IFC #( numeric type m_addr_
                                   , numeric type bram_addr_sz_
                                   , numeric type bram_data_sz_
                                   , numeric type n_brams_);
    (* always_ready *)
    method Maybe #(Data_Mover_Req #(m_addr_, bram_addr_sz_)) data_mover_req;

    (* always_ready *)
    method Maybe #(SHA256_Req #(bram_addr_sz_)) sha256_req;

    (* always_ready *)
    method Maybe #(Tuple2 #(Bool, Bit #(TAdd #(bram_addr_sz_, TLog #(TDiv #(bram_data_sz_, 8)))))) key_pad_ctrl;

    (* always_ready *)
    method Maybe #(Bit #(bram_data_sz_)) key_xor_ctrl;

    (* always_ready *)
    method Bit #(TLog #(n_brams_)) bram_index;

    method Bool run_hash_copy;

    method Action set_verbosity (Bit #(4) new_verb);
endinterface

module mkHWCrypto_Controller #( Source #(Token) src_reg_trigger
                              , Bool data_mover_is_ready
                              , Source #(Token) src_data_mover
                              , Bool sha256_is_ready
                              , Source #(Token) src_sha256
                              , Bool hash_copy_is_ready
                              , Source #(Token) src_hash_copy
                              , HWCrypto_Regs regs)
                              (HWCrypto_Controller_IFC #(m_addr_, bram_addr_sz_, bram_data_sz_, n_brams_))
                              provisos ( Add#(0, 64, m_addr_)
                                       , Add#(a__, TAdd#(bram_addr_sz_, TLog#(TDiv#(bram_data_sz_, 8))), 64)
                                       , Mul#(b__, 8, bram_data_sz_)
                                       , Add#(c__, 8, TMul#(b__, 8)));

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

    RWire #(Data_Mover_Req #(m_addr_, bram_addr_sz_)) rw_data_mover_req <- mkRWire;
    RWire #(SHA256_Req #(bram_addr_sz_)) rw_sha256_req <- mkRWire;
    RWire #(Tuple2 #(Bool, Bit #(TAdd #(bram_addr_sz_, TLog #(TDiv #(bram_data_sz_, 8)))))) rw_key_pad_ctrl <- mkRWire;
    RWire #(Bit #(bram_data_sz_)) rw_key_xor_ctrl <- mkRWire;
    Wire #(Bool) dw_run_hash_copy <- mkDWire (False);

    Reg #(Bit #(64)) rg_chunks_done <- mkRegU;
    Reg #(Bit #(64)) rg_data_chunks_read <- mkRegU;
    Reg #(Bit #(64)) rg_chunks_total <- mkRegU;
    Reg #(Bit #(TAdd #(TLog #(64), 1))) rg_chunk_len <- mkRegU;
    Reg #(Bit #(64)) rg_hash_total_len <- mkRegU;
    Reg #(Bool) rg_chunk_is_first <- mkRegU;
    Reg #(Bool) rg_chunk_is_last <- mkRegU;
    Reg #(Bool) rg_chunk_pad_one <- mkRegU;

    Reg #(Bit #(64)) rg_hash_ptr <- mkRegU;

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
                                && src_reg_trigger.canPeek);
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
    endrule

    rule rl_req_key_short (stack_state.pop_port.canPeek
                           && stack_state.pop_port.peek == REQ_KEY_SHORT
                           && data_mover_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_key_short");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  : regs.key_ptr
                             , bram_addr : 0
                             , dir       : BUS2BRAM
                             , len       : regs.key_len};
        rw_data_mover_req.wset (dm_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_KEY_SHORT);
        if (rg_verbosity > 0) begin
            $display ("    dm_req: ", fshow (dm_req));
            $display ("    going to WAIT_KEY_SHORT");
        end
    endrule

    rule rl_wait_key_short (stack_state.pop_port.canPeek
                            && stack_state.pop_port.peek == WAIT_KEY_SHORT
                            && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_key_short");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_data_mover.drop;
        // now need to prep key
        // skip this for now and get data + hash it
        // TODO might reuse this rule after hashing long keys
        if (regs.key_len < 64) begin
            rw_key_pad_ctrl.wset (tuple2 (True, truncate (regs.key_len)));
        end else if (regs.key_len == 64) begin
            rw_key_pad_ctrl.wset (tuple2 (False, ?));
        end else begin
            // if the key was bigger than 64 bytes, then we will have hashed it
            // down to a 32 byte key
            rw_key_pad_ctrl.wset (tuple2 (True, 32));
        end

        rw_key_xor_ctrl.wset (fn_replicate_byte ('h36));
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (START_INNER_HASH);
    endrule

    rule rl_req_key_long (stack_state.pop_port.canPeek
                          && stack_state.pop_port.peek == REQ_KEY_LONG);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_key_long");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        rg_hash_total_len <= regs.key_len;
        rg_hash_ptr <= regs.key_ptr;
        rg_chunks_done <= 0;
        rg_data_chunks_read <= 0;
        Bit #(TLog #(64)) len_bottom_bits = truncate (regs.key_len);
        let last_over_55 = len_bottom_bits > 55;
        rg_chunks_total <= (regs.key_len >> (log2 (64))) + (last_over_55 ? 2 : 1);

        if (rg_verbosity > 0) begin
            $display ( "    total_len: ", fshow (regs.key_len)
                     , "  len_bottom_bits: ", fshow (len_bottom_bits));
        end
        rw_key_pad_ctrl.wset (tuple2 (False, ?));

        stack_state.pop_port.drop;
        stack_state.put_port[2].put (CONTINUE_WITH_DATA);
        stack_state.put_port[1].put (COPY_HASH);
        stack_state.put_port[0].put (WAIT_KEY_LONG);
    endrule

    rule rl_wait_req_key_long (stack_state.pop_port.canPeek
                               && stack_state.pop_port.peek == WAIT_KEY_LONG);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_req_key_long");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        rw_key_pad_ctrl.wset (tuple2 (True, 32));
        rw_key_xor_ctrl.wset (fn_replicate_byte ('h36));
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (START_INNER_HASH);
    endrule

    rule rl_hash_key_req (stack_state.pop_port.canPeek
                          && stack_state.pop_port.peek == HASH_KEY_REQ
                          && sha256_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_hash_key_req");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : truncate (regs.key_len)
                         , reset_hash : True
                         // TODO change this
                         , pad_zeroes : True
                         , pad_one    : True
                         , append_len : True};
        rw_sha256_req.wset (sha_req);
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
                              && sha256_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_start_inner_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : 64
                         , reset_hash : True
                         , pad_one    : False
                         , pad_zeroes : True
                         , append_len : False};
        rw_sha256_req.wset (sha_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (CONTINUE_INNER_HASH);
    endrule

    // set up for fetching data from memory to the data bram and hashing it
    rule rl_continue_inner_hash (stack_state.pop_port.canPeek
                                 && stack_state.pop_port.peek == CONTINUE_INNER_HASH
                                 && src_sha256.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_continue_inner_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_sha256.drop;

        rg_bram_index <= 1;
        stack_state.pop_port.drop;
        stack_state.put_port[2].put (CONTINUE_WITH_DATA);
        stack_state.put_port[1].put (COPY_HASH);
        stack_state.put_port[0].put (OUTER_HASH);
        rg_bram_index_next <= 0;
        rg_replicate_byte <= 'h5c;
        let total_len = regs.data_len + 64;
        rg_hash_total_len <= total_len;
        rg_hash_ptr <= regs.data_ptr;
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
    endrule

    // continue the inner hash by fetching data and hashing it
    rule rl_continue_hash_with_data (stack_state.pop_port.canPeek
                                     && stack_state.pop_port.peek == CONTINUE_WITH_DATA
                                     && data_mover_is_ready);
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
                rw_data_mover_req.wset (dm_req);
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
                       && src_data_mover.canPeek
                       && sha256_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_read");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_data_mover.drop;
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : zeroExtend (rg_chunk_len)
                         , reset_hash : rg_chunk_is_first
                         , pad_zeroes : True
                         , pad_one    : rg_chunk_pad_one
                         , append_len : rg_chunk_is_last};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end

        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_req_hash (stack_state.pop_port.canPeek
                      && stack_state.pop_port.peek == REQ_HASH
                      && sha256_is_ready);
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
                         , pad_zeroes : True
                         , pad_one    : rg_chunk_pad_one
                         , append_len : rg_chunk_is_last};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end

        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_wait_hash (stack_state.pop_port.canPeek
                       && stack_state.pop_port.peek == WAIT_HASH
                       && src_sha256.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_sha256.drop;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (CONTINUE_WITH_DATA);
        rg_chunks_done <= rg_chunks_done + 1;
    endrule

    rule rl_wait_data (stack_state.pop_port.canPeek
                       && stack_state.pop_port.peek == WAIT_DATA
                       && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_data");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_data_mover.drop;

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr  : 0
                         , len        : truncate (regs.data_len)
                         , reset_hash : True
                         , pad_zeroes : True
                         , pad_one    : True
                         , append_len : True};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_HASH);
    endrule

    rule rl_copy_hash_to_data_bram (stack_state.pop_port.canPeek
                                    && stack_state.pop_port.peek == COPY_HASH
                                    && hash_copy_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_copy_hash_to_data_bram");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        dw_run_hash_copy <= True;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_COPY_HASH);
    endrule

    Reg #(Bool) rg_key_hash_req <- mkRegU;
    Reg #(Bool) rg_key_hash_done <- mkRegU;
    Reg #(Bool) rg_data_hash_done <- mkRegU;
    rule rl_wait_copy_hash (stack_state.pop_port.canPeek
                            && stack_state.pop_port.peek == WAIT_COPY_HASH
                            && src_hash_copy.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_copy_hash");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_hash_copy.drop;
        rg_bram_index <= rg_bram_index_next;
        rg_key_hash_req <= False;
        rg_key_hash_done <= False;
        rg_data_hash_done <= False;
        rw_key_xor_ctrl.wset (fn_replicate_byte (rg_replicate_byte));
        stack_state.pop_port.drop;
    endrule

    rule rl_outer_hash (stack_state.pop_port.canPeek
                        && stack_state.pop_port.peek == OUTER_HASH
                        && sha256_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_outer_hash");
            $display ("    rg_key_hash_req: ", fshow (rg_key_hash_req));
            $display ("    rg_key_hash_done: ", fshow (rg_key_hash_done));
            $display ("    rg_data_hash_done: ", fshow (rg_data_hash_done));
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
                             , pad_zeroes : True
                             , pad_one    : False
                             , append_len : False};
            rw_sha256_req.wset (sha_req);
        end else if (rg_key_hash_req && !rg_key_hash_done && src_sha256.canPeek) begin
            $display ("    case 2");
            rg_bram_index <= 1;
            rg_key_hash_done <= True;
        end else if (rg_key_hash_done && !rg_data_hash_done && src_sha256.canPeek) begin
            $display ("    case 3");
            src_sha256.drop;
            rg_data_hash_done <= True;
            SHA256_Req #(bram_addr_sz_) sha_req
                = SHA256_Req { bram_addr  : 0
                             , len        : 32
                             , reset_hash : False
                             , pad_zeroes : True
                             , pad_one    : True
                             , append_len : True};
            rw_sha256_req.wset (sha_req);
        end else if (rg_key_hash_done && rg_data_hash_done && src_sha256.canPeek) begin
            $display ("    case 4");
            src_sha256.drop;
            rg_replicate_byte <= 0;
            rg_bram_index_next <= 1;
            stack_state.pop_port.drop;
            stack_state.put_port[1].put (COPY_HASH);
            stack_state.put_port[0].put (WRITE_BACK);
        end
    endrule

    rule rl_write_back_to_mem (stack_state.pop_port.canPeek
                               && stack_state.pop_port.peek == WRITE_BACK
                               && data_mover_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_write_back_to_mem");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  : regs.dest_ptr
                             , bram_addr : 0
                             , dir       : BRAM2BUS
                             , len       : 32};
        rw_data_mover_req.wset (dm_req);
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (WAIT_WRITE_BACK);
    endrule

    rule rl_wait_write_back (stack_state.pop_port.canPeek
                             && stack_state.pop_port.peek == WAIT_WRITE_BACK
                             && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_write_back");
        end
        if (rg_verbosity > 1) begin
            stack_state.print_state;
        end
        src_data_mover.drop;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (FINISH);
    endrule

    rule rl_finish (stack_state.pop_port.canPeek
                    && stack_state.pop_port.peek == FINISH);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_finish");
            $display ("    cycles counted: ", fshow (rg_cycle_counter));
        end
        src_reg_trigger.drop;
        stack_state.pop_port.drop;
        stack_state.put_port[0].put (IDLE);
    endrule


    method data_mover_req = rw_data_mover_req.wget;
    method sha256_req = rw_sha256_req.wget;
    method key_pad_ctrl = rw_key_pad_ctrl.wget;
    method key_xor_ctrl = rw_key_xor_ctrl.wget;
    method bram_index = rg_bram_index;
    method run_hash_copy = dw_run_hash_copy;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod
endmodule




endpackage
