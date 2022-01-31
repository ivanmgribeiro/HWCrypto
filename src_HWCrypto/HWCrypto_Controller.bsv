package HWCrypto_Controller;

import HWCrypto_Types :: *;
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
    WAIT_HASH,
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

    method Action set_verbosity (Bit #(4) new_verb);
endinterface

module mkHWCrypto_Controller #( Source #(Token) src_reg_trigger
                              , Bool data_mover_is_ready
                              , Source #(Token) src_data_mover
                              , Bool sha256_is_ready
                              , Source #(Token) src_sha256
                              , HWCrypto_Regs regs)
                              (HWCrypto_Controller_IFC #(m_addr_, bram_addr_sz_, bram_data_sz_, n_brams_))
                              provisos ( Add#(0, 64, m_addr_)
                                       , Add#(a__, TAdd#(bram_addr_sz_, TLog#(TDiv#(bram_data_sz_, 8))), 64)
                                       , Mul#(b__, 8, bram_data_sz_)
                                       , Add#(c__, 8, TMul#(b__, 8)));

    Reg #(State) rg_state <- mkReg (IDLE);
    Reg #(State) rg_state_next <- mkRegU;
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    Reg #(Bit #(64)) rg_hash_chunk_ctr <- mkReg (0);
    Reg #(Bit #(TLog #(n_brams_))) rg_bram_index <- mkReg (0);

    RWire #(Data_Mover_Req #(m_addr_, bram_addr_sz_)) rw_data_mover_req <- mkRWire;
    RWire #(SHA256_Req #(bram_addr_sz_)) rw_sha256_req <- mkRWire;
    RWire #(Tuple2 #(Bool, Bit #(TAdd #(bram_addr_sz_, TLog #(TDiv #(bram_data_sz_, 8)))))) rw_key_pad_ctrl <- mkRWire;
    RWire #(Bit #(bram_data_sz_)) rw_key_xor_ctrl <- mkRWire;

    Reg #(Bit #(64)) rg_chunks_done <- mkRegU;
    Reg #(Bit #(TAdd #(TLog #(64), 1))) rg_chunk_len <- mkRegU;
    Reg #(Bool) rg_chunk_is_first <- mkRegU;
    Reg #(Bool) rg_chunk_is_last <- mkRegU;

    function Bit #(TMul #(n_, 8)) fn_replicate_byte (Bit #(8) value)
        provisos (Add#(z__, 8, TMul#(n_, 8)));
        Bit #(TMul #(n_, 8)) res = 0;
        for (Integer i = 0; i < valueOf (n_); i = i+1) begin
            res[i*8 + 7:i*8] = value;
        end
        return res;
    endfunction

    rule rl_handle_reg_trigger (rg_state == IDLE
                                && src_reg_trigger.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_handle_reg_trigger");
        end
        // keys longer than 64 bytes (block size) need to be hashed
        if (regs.key_len > 64) begin
            if (rg_verbosity > 0) begin
                $display ("    going to REQ_KEY_LONG");
            end
            //rg_state <= REQ_KEY_LONG;
            rg_state <= REQ_DATA;
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    going to REQ_KEY_SHORT");
            end
            //rg_state <= REQ_KEY_SHORT;
            rg_state <= REQ_DATA;
        end
        rg_bram_index <= 0;
        rg_chunks_done <= 0;
    endrule

    rule rl_req_key_short (rg_state == REQ_KEY_SHORT
                             && data_mover_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_key_short");
        end
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  : regs.key_ptr
                             , bram_addr : 0
                             , dir       : BUS2BRAM
                             , len       : regs.key_len};
        rw_data_mover_req.wset (dm_req);
        rg_state <= WAIT_KEY_SHORT;
        if (rg_verbosity > 0) begin
            $display ("    dm_req: ", fshow (dm_req));
            $display ("    going to WAIT_KEY_SHORT");
        end
    endrule

    rule rl_wait_key_short (rg_state == WAIT_KEY_SHORT
                            && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_key_short");
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

        rg_state <= HASH_KEY_REQ;
    endrule

    rule rl_hash_key_req (rg_state == HASH_KEY_REQ
                          && sha256_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_hash_key_req");
        end

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr : 0
                         , len       : truncate (regs.key_len)
                         , is_first  : True
                         // TODO change this
                         , is_last   : True};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end
        rg_state <= WAIT_HASH;
    endrule



    rule rl_req_data (rg_state == REQ_DATA
                      && data_mover_is_ready);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_data");
        end

        // find the number of 64byte chunks that we will need
        Bit #(TLog #(64)) len_bottom_bits = truncate (regs.data_len);
        Bit #(1) bottom_red = reduceOr (len_bottom_bits);
        Bool last_is_full = bottom_red == 1'b0;
        let num_chunks = (regs.data_len >> (log2 (64))) + zeroExtend (bottom_red);
        if (rg_verbosity > 0) begin
            $display ( "    num_chunks: ", fshow (num_chunks)
                     , "  rg_chunks_done: ", fshow (rg_chunks_done)
                     , "  last_is_full: ", fshow (last_is_full));
        end

        if (rg_chunks_done == num_chunks) begin
            // we are done
            rg_state <= FINISH;
        end else begin
            let is_last = rg_chunks_done == num_chunks - 1;
            // request the next chunk from memory and hash it
            let len = is_last && !last_is_full ? zeroExtend (len_bottom_bits) : 64;
            Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
                = Data_Mover_Req { bus_addr  : regs.data_ptr + (rg_chunks_done << log2 (64))
                                 , bram_addr : 0
                                 , dir       : BUS2BRAM
                                 , len       : len};
            rw_data_mover_req.wset (dm_req);
            if (rg_verbosity > 0) begin
                $display ("    dm_req: ", fshow (dm_req));
                $display ("    going to WAIT_DATA");
            end
            rg_state <= WAIT_READ;
            rg_chunk_len <= len;
            rg_chunk_is_last <= is_last;
            rg_chunk_is_first <= rg_chunks_done == 0;
            rg_state_next <= REQ_DATA;
        end
    endrule

    rule rl_wait_read (rg_state == WAIT_READ
                       && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_read");
        end
        src_data_mover.drop;
        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr : 0
                         , len       : zeroExtend (rg_chunk_len)
                         , is_first  : rg_chunk_is_first
                         , is_last   : rg_chunk_is_last};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end

        rg_state <= WAIT_HASH;
    endrule

    rule rl_wait_hash (rg_state == WAIT_HASH
                       && src_sha256.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_wait_read");
        end
        src_sha256.drop;
        rg_state <= rg_state_next;
        rg_chunks_done <= rg_chunks_done + 1;
    endrule

    rule rl_wait_data (rg_state == WAIT_DATA
                       && src_data_mover.canPeek);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto Controller rl_req_data");
        end
        src_data_mover.drop;

        SHA256_Req #(bram_addr_sz_) sha_req
            = SHA256_Req { bram_addr : 0
                         , len       : truncate (regs.data_len)
                         , is_first  : True
                         , is_last   : True};
        rw_sha256_req.wset (sha_req);
        if (rg_verbosity > 0) begin
            $display ("    sha_req: ", fshow (sha_req));
            $display ("    going to WAIT_HASH");
        end
        rg_state <= WAIT_HASH;
    endrule

    method data_mover_req = rw_data_mover_req.wget;
    method sha256_req = rw_sha256_req.wget;
    method key_pad_ctrl = rw_key_pad_ctrl.wget;
    method key_xor_ctrl = rw_key_xor_ctrl.wget;
    method bram_index = rg_bram_index;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod
endmodule




endpackage
