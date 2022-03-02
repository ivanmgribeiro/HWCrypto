package HWCrypto_SHA256;

import SourceSink :: *;
import HWCrypto_Types :: *;
import HWCrypto_Utils :: *;
import BRAMCore :: *;
import Vector :: *;

typedef enum {
    IDLE,
    READ,
    SCHED,
    PREP_COMPRESS,
    COMPRESS,
    FINISH
} State deriving (Bits, Eq, FShow);

interface HWCrypto_SHA256_IFC;
    method Action request (SHA256_Req req);
    method Bool is_ready;
    method Vector #(8, Bit #(32)) hash_regs;
    method Action set_verbosity (Bit #(4) new_verb);
endinterface

// TODO variable number of rounds per cycle?
module mkHWCrypto_SHA256 #(Vector #(64, Reg #(Bit #(32))) v_rg_hashdata,
                           Sink #(Token) snk)
                          (HWCrypto_SHA256_IFC);

    Vector #(8, Reg #(Bit #(32))) v_rg_hash = newVector;
    v_rg_hash[0] <- mkReg ('h6A09E667); v_rg_hash[1] <- mkReg ('hBB67AE85); v_rg_hash[2] <- mkReg ('h3C6EF372); v_rg_hash[3] <- mkReg ('hA54FF53A);
    v_rg_hash[4] <- mkReg ('h510E527F); v_rg_hash[5] <- mkReg ('h9B05688C); v_rg_hash[6] <- mkReg ('h1F83D9AB); v_rg_hash[7] <- mkReg ('h5BE0CD19);

    Vector #(8, Reg #(Bit #(32))) v_rg_acc <- replicateM (mkRegU);

    Vector #(64, Bit #(32)) v_round_const = newVector;
    v_round_const[0]  = 'h428A2F98; v_round_const[1]  = 'h71374491; v_round_const[2]  = 'hB5C0FBCF; v_round_const[3]  = 'hE9B5DBA5;
    v_round_const[4]  = 'h3956C25B; v_round_const[5]  = 'h59F111F1; v_round_const[6]  = 'h923F82A4; v_round_const[7]  = 'hAB1C5ED5;
    v_round_const[8]  = 'hD807AA98; v_round_const[9]  = 'h12835B01; v_round_const[10] = 'h243185BE; v_round_const[11] = 'h550C7DC3;
    v_round_const[12] = 'h72BE5D74; v_round_const[13] = 'h80DEB1FE; v_round_const[14] = 'h9BDC06A7; v_round_const[15] = 'hC19BF174;
    v_round_const[16] = 'hE49B69C1; v_round_const[17] = 'hEFBE4786; v_round_const[18] = 'h0FC19DC6; v_round_const[19] = 'h240CA1CC;
    v_round_const[20] = 'h2DE92C6F; v_round_const[21] = 'h4A7484AA; v_round_const[22] = 'h5CB0A9DC; v_round_const[23] = 'h76F988DA;
    v_round_const[24] = 'h983E5152; v_round_const[25] = 'hA831C66D; v_round_const[26] = 'hB00327C8; v_round_const[27] = 'hBF597FC7;
    v_round_const[28] = 'hC6E00BF3; v_round_const[29] = 'hD5A79147; v_round_const[30] = 'h06CA6351; v_round_const[31] = 'h14292967;
    v_round_const[32] = 'h27B70A85; v_round_const[33] = 'h2E1B2138; v_round_const[34] = 'h4D2C6DFC; v_round_const[35] = 'h53380D13;
    v_round_const[36] = 'h650A7354; v_round_const[37] = 'h766A0ABB; v_round_const[38] = 'h81C2C92E; v_round_const[39] = 'h92722C85;
    v_round_const[40] = 'hA2BFE8A1; v_round_const[41] = 'hA81A664B; v_round_const[42] = 'hC24B8B70; v_round_const[43] = 'hC76C51A3;
    v_round_const[44] = 'hD192E819; v_round_const[45] = 'hD6990624; v_round_const[46] = 'hF40E3585; v_round_const[47] = 'h106AA070;
    v_round_const[48] = 'h19A4C116; v_round_const[49] = 'h1E376C08; v_round_const[50] = 'h2748774C; v_round_const[51] = 'h34B0BCB5;
    v_round_const[52] = 'h391C0CB3; v_round_const[53] = 'h4ED8AA4A; v_round_const[54] = 'h5B9CCA4F; v_round_const[55] = 'h682E6FF3;
    v_round_const[56] = 'h748F82EE; v_round_const[57] = 'h78A5636F; v_round_const[58] = 'h84C87814; v_round_const[59] = 'h8CC70208;
    v_round_const[60] = 'h90BEFFFA; v_round_const[61] = 'hA4506CEB; v_round_const[62] = 'hBEF9A3F7; v_round_const[63] = 'hC67178F2;

    Wire #(Bool) dw_cycle_counter_reset <- mkDWire (False);
    Reg #(Bit #(64)) rg_cycle_counter <- mkReg (0);

    // TODO smaller counter, max 48
    Reg #(Bit #(16)) rg_rnd_ctr <- mkRegU;
    Reg #(Bit #(3)) rg_read_ctr <- mkRegU;
    Reg #(Bit #(32)) rg_len <- mkReg (0);
    Reg #(Bit #(32)) rg_len_this <- mkReg (0);
    Reg #(Bool) rg_pad_one <- mkRegU;
    Reg #(Bool) rg_append_len <- mkRegU;

    Reg #(State) rg_state <- mkReg (IDLE);
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);

    Reg #(Bit #(TAdd #(3, 1))) rg_int_base <- mkRegU;

    function Bit #(n_) rotate_right_by (Bit #(n_) bits, Integer amt);
        return reverseBits (rotateBitsBy (reverseBits (bits), fromInteger (amt)));
    endfunction

    // if the lowest bit of the address is 1, read the upper bits, otherwise
    // read the lower bits
    // TODO generalise this?
    function Bit #(32) fn_read_32_from_64 (Bit #(64) data, Bit #(1) addr);
        return addr == 1'b1 ? truncateLSB (data) : truncate (data);
    endfunction

    // expected combinations of pad and append_len:
    // pad_zeroes False, pad_one False, append_len False    default
    // pad_zeroes True,  pad_one False, append_len True     56-63 last chunk
    // pad_zeroes True,  pad_one True,  append_len False    56-63 second last chunk
    // pad_zeroes True,  pad_one True,  append_len True     0-55 last chunk
    // other combinations are not supported
    //function Bit #(64) fn_read_modified ( Bit #(3) addr
    //                                               , Bit #(64) raw
    //                                               , Bit #(32) len_total
    //                                               , Bit #(32) len_this
    //                                               , Bool pad_one
    //                                               , Bool append_len);
    //    // TODO there should be something in the BRAM that handles zeroing.
    //    // have a look to see if this is still necessary
    //    Bit #(3) zero_start_addr = truncate (len_this >> fromInteger (valueOf (TLog #(TDiv #(64, 8)))));
    //    Integer zero_end_addr = valueOf (TDiv #(512, 64));
    //    if (addr < zero_start_addr) begin
    //        return raw;
    //    end else if (addr >= fromInteger (zero_end_addr)) begin
    //        return raw;
    //    end else if (addr == zero_start_addr) begin
    //        Bit #((TLog #(64))) lsb = truncate (len_this);
    //        Integer shamt = valueOf (TLog #(TDiv #(64, 8)));
    //        let raw_mask = ~(~0 << (lsb << shamt));
    //        let other = zeroExtend ({pad_one ? 1'b1 : 1'b0, 7'b0}) << (lsb << shamt);
    //        return other | (raw & raw_mask);
    //    end else if (append_len && addr == fromInteger (512/valueOf (64) - 1)) begin
    //        return fn_rev_byte_order (zeroExtend (len_total << 3));
    //    end else begin
    //        return 0;
    //    end
    //endfunction

    rule rl_incr_counter;
        if (dw_cycle_counter_reset) begin
            rg_cycle_counter <= 0;
        end else begin
            rg_cycle_counter <= rg_cycle_counter + 1;
        end
    endrule

    //// read the following offsets from the current BRAM address2321
    //rule rl_read_regs (rg_state == READ);
    //    if (rg_verbosity > 0) begin
    //        $display ("%m HWCrypto SHA256 rl_read_regs:");
    //    end

    //    Bit #(TAdd #(, 1)) round_base_addr = rg_int_base + zeroExtend (rg_rnd_ctr);
    //    Bit #(1) bottom_bit = round_base_addr[0];

    //    let offset = 7;
    //    let raw_data = bram.read;
    //    let mod_data = fn_read_modified ( rg_last_addr
    //                                    , raw_data
    //                                    , rg_len
    //                                    , rg_len_this
    //                                    , rg_pad_one
    //                                    , rg_append_len);
    //    let data = fn_read_32_from_64 (mod_data, bottom_bit);
    //    case (rg_read_ctr)
    //        3'b000: begin
    //            offset = 15;
    //        end
    //        3'b001: begin
    //            offset = 2;
    //            data = fn_read_32_from_64 (mod_data, ~bottom_bit);
    //            rg_15 <= data;
    //        end
    //        3'b010: begin
    //            offset = 16;
    //            data = fn_read_32_from_64 (mod_data,  bottom_bit);
    //            rg_2 <= data;
    //        end
    //        3'b011: begin
    //            offset = 7;
    //            data = fn_read_32_from_64 (mod_data,  bottom_bit);
    //            rg_16 <= data;
    //        end
    //        3'b100: begin
    //            data = fn_read_32_from_64 (mod_data, ~bottom_bit);
    //            rg_7 <= data;
    //        end
    //        default: begin
    //            // we should never reach this
    //            $display ("%m HWCrypto SHA256: ERROR: rl_read_regs reached default case");
    //        end
    //    endcase

    //    Bit #(TAdd #(3, 1)) read_addr = round_base_addr - offset;

    //    if (rg_verbosity > 0) begin
    //        $display ("    bram.read: ", fshow (bram.read), "  mod_data: ", fshow (mod_data), "  extracted: ", fshow (data));
    //        $display ( "    offset: ", fshow (offset)
    //                 , "  rg_bram_base: ", fshow (rg_bram_base)
    //                 , "  rg_read_ctr: ", fshow (rg_read_ctr));
    //    end

    //    if (rg_read_ctr == 3'b100) begin
    //        rg_state <= SCHED;
    //        bram.put (False, truncateLSB (round_base_addr), ?);
    //        rg_last_addr <= truncateLSB (round_base_addr);
    //        if (rg_verbosity > 0) begin
    //            Bit #(bram_addr_sz_) addr = truncateLSB (round_base_addr);
    //            $display ("    reading finished, requesting read of ", fshow (addr), " and going to SCHED");
    //        end
    //    end else begin
    //        bram.put (False, truncateLSB (read_addr), ?);
    //        rg_last_addr <= truncateLSB (read_addr);
    //        if (rg_verbosity > 0) begin
    //            Bit #(bram_addr_sz_) addr = truncateLSB (read_addr);
    //            $display ("    continuing read, requesting read of ", fshow (addr));
    //        end
    //    end
    //    rg_read_ctr <= rg_read_ctr + 1;
    //endrule

    rule rl_round_sched (rg_state == SCHED);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto SHA256 rl_round_sched");
        end
        Bit #(TLog #(64)) addr = truncate (rg_rnd_ctr);
        let val_15 = fn_rev_byte_order (v_rg_hashdata[addr - 15]);
        let val_2  = fn_rev_byte_order (v_rg_hashdata[addr -  2]);
        let val_16 = fn_rev_byte_order (v_rg_hashdata[addr - 16]);
        let val_7  = fn_rev_byte_order (v_rg_hashdata[addr -  7]);
        let s0 = (rotate_right_by (val_15,  7)) ^ (rotate_right_by (val_15, 18)) ^ (val_15 >>  3);
        let s1 = (rotate_right_by (val_2, 17)) ^ (rotate_right_by (val_2, 19)) ^ (val_2 >> 10);
        let sum = val_16 + s0 + val_7 + s1;
        let sum_rev = fn_rev_byte_order (sum);
        Bit #(32) data = sum_rev;
        if (rg_verbosity > 1) begin
            $display ( "    inputs -"
                     , "  val_15: ", fshow (val_15)
                     , "  val_2: ", fshow (val_2)
                     , "  val_16: ", fshow (val_16)
                     , "  val_7: ", fshow (val_7));
            $display ( "    round constants -"
                     , "  s0: ", fshow (s0)
                     , "  s1: ", fshow (s1)
                     , "  sum: ", fshow (sum));
        end
        if (rg_verbosity > 0) begin
            $display ( "    addr: ", fshow (addr)
                     , "  data: ", fshow (data));
        end

        //bram.put (True, truncateLSB (addr), data);
        v_rg_hashdata[addr] <= data;

        if (rg_rnd_ctr < 63) begin
            rg_rnd_ctr <= rg_rnd_ctr + 1;
        end else begin
            for (Integer i = 0; i < 8; i = i+1) begin
                v_rg_acc[i] <= v_rg_hash[i];
            end
            rg_state <= COMPRESS;
            if (rg_verbosity > 0) begin
                $display ("    schedule done, going to COMPRESS");
            end
            rg_rnd_ctr <= 0;
        end
    endrule

    //rule rl_prep_compress (rg_state == PREP_COMPRESS);
    //    Bit #(TLog #(64)) bram_addr = truncateLSB (rg_bram_base);
    //    if (rg_verbosity > 0) begin
    //        $display ("%m HWCrypto SHA256 rl_prep_compress");
    //        $display ("    reading address ", fshow (rg_bram_base));
    //    end
    //    bram.put (False, bram_addr, ?);
    //    rg_last_addr <= truncateLSB (bram_addr);
    //    rg_state <= COMPRESS;
    //endrule

    rule rl_round_compress (rg_state == COMPRESS);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto SHA256 rl_round_compress");
        end
        //let mod_data = fn_read_modified ( rg_last_addr
        //                                , bram.read
        //                                , rg_len
        //                                , rg_len_this
        //                                , rg_pad_one
        //                                , rg_append_len);
        Bit #(TLog #(64)) rgindex = truncate (rg_rnd_ctr);
        let data = v_rg_hashdata[rgindex];

        let a = v_rg_acc[0]; let b = v_rg_acc[1]; let c = v_rg_acc[2]; let d = v_rg_acc[3];
        let e = v_rg_acc[4]; let f = v_rg_acc[5]; let g = v_rg_acc[6]; let h = v_rg_acc[7];
        let w = fn_rev_byte_order (data);
        if (rg_verbosity > 1) begin
            $display ( "    inputs -  ", fshow (readVReg (v_rg_acc))
                     //, "  bram.read: ", fshow (bram.read)
                     , "  data: ", fshow (data)
                     , "  w: ", fshow (w));
        end

        let s1 = (rotate_right_by (e, 6)) ^ (rotate_right_by (e, 11)) ^ (rotate_right_by (e, 25));
        let ch = (e & f) ^ (~e & g);
        let temp1 = h + s1 + ch + v_round_const[rg_rnd_ctr] + w;
        let s0 = (rotate_right_by (a, 2)) ^ (rotate_right_by (a, 13)) ^ (rotate_right_by (a, 22));
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0 + maj;

        if (rg_verbosity > 1) begin
            $display ( "    intermediates -"
                     , "  s1: ", fshow (s1)
                     , "  ch: ", fshow (ch)
                     , "  temp1: ", fshow (temp1)
                     , "  s0: ", fshow (s0)
                     , "  maj: ", fshow (maj)
                     , "  temp2: ", fshow (temp2));
        end

        v_rg_acc[0] <= temp1 + temp2;
        v_rg_acc[1] <= a;
        v_rg_acc[2] <= b;
        v_rg_acc[3] <= c;
        v_rg_acc[4] <= d + temp1;
        v_rg_acc[5] <= e;
        v_rg_acc[6] <= f;
        v_rg_acc[7] <= g;

        let rnd_ctr_incr = rg_rnd_ctr + 1;
        //bram.put (False, bram_addr, ?);
        rg_rnd_ctr <= rnd_ctr_incr;
        if (rg_rnd_ctr == 63) begin
            $display ("    hash done; going to FINISH");
            rg_state <= FINISH;
        end
    endrule

    rule rl_finish (rg_state == FINISH);
        if (rg_verbosity > 0) begin
            $display ("HWCrypto SHA256 rl_finish");
            $display ("    cycle counter: ", fshow (rg_cycle_counter));
            $display ("    final hash:");
        end
        for (Integer i = 0; i < 8; i = i+1) begin
            let hash_val = v_rg_hash[i] + v_rg_acc[i];
            v_rg_hash[i] <= hash_val;
            if (rg_verbosity > 0) begin
                $display ("        h%1d", i, ": ", fshow (hash_val), "  v_rg_hash: ", fshow (v_rg_hash[i]), "  v_rg_acc[i]: ", fshow (v_rg_acc[i]));
            end
        end
        rg_state <= IDLE;
        snk.put (?);
    endrule


    // TODO make length type more general
    // Assumes that the next 1536 bits of the BRAM are also clear (ie there are 512b of data and 2048b
    // of scratch space in total including data)
    method Action request (SHA256_Req req) if (rg_state == IDLE);
        let len        = req.len;
        let reset_hash = req.reset_hash;
        let pad_one    = req.pad_one;
        let append_len = req.append_len;

        let len_so_far = (reset_hash ? 0 : rg_len) + len;
        rg_len <= len_so_far;
        rg_len_this <= len;

        // TODO fix this
        // for now, assume we always have 512b inputs
        rg_rnd_ctr <= 16;
        rg_read_ctr <= 0;
        rg_int_base <= 0;
        if (rg_verbosity > 0) begin
            $display ( "%m HWCrypto SHA256 - request");
            $display ( "    req: ", fshow (req));
        end
        if (reset_hash) begin
            v_rg_hash[0] <= 'h6A09E667; v_rg_hash[1] <= 'hBB67AE85; v_rg_hash[2] <= 'h3C6EF372; v_rg_hash[3] <= 'hA54FF53A;
            v_rg_hash[4] <= 'h510E527F; v_rg_hash[5] <= 'h9B05688C; v_rg_hash[6] <= 'h1F83D9AB; v_rg_hash[7] <= 'h5BE0CD19;
        end
        if (pad_one && append_len && len >= 56) begin
            // the controller should make sure this never happens
            $display ("HWCrypto SHA256 ERROR: requesting one and append len; there is not enough space");
        end else begin
            if (pad_one) begin
                Bit #(TLog #(64)) rgindex = truncate (len >> 2);
                Bit #(2) len_lsb = truncate (len);
                Bit #(5) shamt = zeroExtend (len_lsb) << 3;
                let old_data = v_rg_hashdata[rgindex];
                let one_byte = zeroExtend ({1'b1, 7'b0}) << shamt;
                Bit #(32) data_mask = zeroExtend (8'hff) << shamt;
                let new_data = (old_data & ~data_mask) | (one_byte & data_mask);
                v_rg_hashdata[rgindex] <= new_data;
                if (rg_verbosity > 0) begin
                    $display ("    appending one, addr: ", fshow (rgindex)
                              , "  len_lsb: ", fshow (len_lsb)
                              , "  shamt: ", fshow (shamt)
                              , "  byte+mask: ", fshow (one_byte & data_mask)
                              , "  old_data: ", fshow (old_data)
                              , "  new_data: ", fshow (new_data));
                end
            end
            if (append_len) begin
                v_rg_hashdata[15] <= fn_rev_byte_order (len_so_far << 3);
            end
        end
        rg_append_len <= append_len;
        rg_pad_one <= pad_one;
        rg_state <= SCHED;
        dw_cycle_counter_reset <= True;
    endmethod

    method hash_regs = readVReg (v_rg_hash);

    method Bool is_ready = rg_state == IDLE;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod
endmodule


endpackage
