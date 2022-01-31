package HWCrypto_Controller;

import HWCrypto_Types :: *;
import RWire :: *;
import SourceSink :: *;

typedef enum {
    IDLE,
    REQ_KEY_SHORT,
    REQ_KEY_LONG,
    WAIT_KEY_SHORT,
    WAIT_KEY_LONG,
    HASH_KEY_REQ,
    REQ_DATA,
    WAIT_DATA,
    WAIT_HASH
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
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    Reg #(Bit #(64)) rg_hash_chunk_ctr <- mkReg (0);
    Reg #(Bit #(TLog #(n_brams_))) rg_bram_index <- mkReg (0);

    RWire #(Data_Mover_Req #(m_addr_, bram_addr_sz_)) rw_data_mover_req <- mkRWire;
    RWire #(SHA256_Req #(bram_addr_sz_)) rw_sha256_req <- mkRWire;
    RWire #(Tuple2 #(Bool, Bit #(TAdd #(bram_addr_sz_, TLog #(TDiv #(bram_data_sz_, 8)))))) rw_key_pad_ctrl <- mkRWire;
    RWire #(Bit #(bram_data_sz_)) rw_key_xor_ctrl <- mkRWire;

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
            rg_state <= REQ_KEY_LONG;
        end else begin
            if (rg_verbosity > 0) begin
                $display ("    going to REQ_KEY_SHORT");
            end
            rg_state <= REQ_KEY_SHORT;
        end
        rg_bram_index <= 0;
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
        // TODO handle long data
        // for now just assume it is <512b
        Data_Mover_Req #(m_addr_, bram_addr_sz_) dm_req
            = Data_Mover_Req { bus_addr  : regs.data_ptr
                             , bram_addr : 0
                             , dir       : BUS2BRAM
                             , len       : regs.data_len};
        rw_data_mover_req.wset (dm_req);
        if (rg_verbosity > 0) begin
            $display ("    dm_req: ", fshow (dm_req));
            $display ("    going to WAIT_DATA");
        end
        rg_state <= WAIT_DATA;
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
