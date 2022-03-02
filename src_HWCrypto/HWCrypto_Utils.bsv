package HWCrypto_Utils;

import BRAMCore :: *;
import Vector :: *;
import SourceSink :: *;
import HWCrypto_Types :: *;

interface BRAM_PORT_XOR #(type addr_t_, type data_t_);
    interface BRAM_PORT #(addr_t_, data_t_) bram;
    method Action set_xor (Bit #(SizeOf #(data_t_)) new_xor);
    // the address for set_pad_start is a byte address
    method Action set_pad (Bool set, Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8)))) start);
endinterface

interface BRAM_DP_XOR_IFC #(type addr_t_, type data_t_);
    interface BRAM_DUAL_PORT #(addr_t_, data_t_) bram;
    method Action set_xor (Bit #(SizeOf #(data_t_)) new_xor);
    // the address for set_pad_start is a byte address
    method Action set_pad (Bool set, Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8)))) start);
endinterface

module mkBRAM_PORT_XOR #(BRAM_PORT #(addr_t_, data_t_) bram_i)
                        (BRAM_PORT_XOR #(addr_t_, data_t_))
                        provisos (Bits#(data_t_, data_t_sz_)
                                 , Bits #(addr_t_, addr_t_sz_)
                                 , Add #(a__, TLog #(TDiv #(data_t_sz_, 8)), TLog #(data_t_sz_)));
    Reg #(Bit #(SizeOf #(data_t_))) rg_xor <- mkReg (0);
    Reg #(Bool) rg_use_xor <- mkRegU;
    Reg #(Bool) rg_pad_set <- mkReg (False);
    Reg #(Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8))))) rg_pad_start <- mkRegU;
    Reg #(Bit #(SizeOf #(data_t_))) rg_mask <- mkReg (~0);

    interface BRAM_PORT bram;
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
    endinterface

    method Action set_xor (Bit #(SizeOf #(data_t_)) new_xor);
        rg_xor <= new_xor;
    endmethod

    method Action set_pad (Bool set, Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8)))) start);
        rg_pad_set <= set;
        rg_pad_start <= start;
    endmethod
endmodule

module mkBRAM_DP_XOR #(BRAM_DUAL_PORT #(addr_t_, data_t_) bram_i)
                             (BRAM_DP_XOR_IFC #(addr_t_, data_t_))
                             provisos ( Bits #(addr_t_, addr_t_sz_)
                                      , Bits #(data_t_, data_t_sz_)
                                      , Add#(a__, TLog#(TDiv#(data_t_sz_, 8)), TLog#(data_t_sz_)));
    let bram_a <- mkBRAM_PORT_XOR (bram_i.a);
    let bram_b <- mkBRAM_PORT_XOR (bram_i.b);
    interface BRAM_DUAL_PORT bram;
        interface a = bram_a.bram;
        interface b = bram_b.bram;
    endinterface
    method Action set_xor (Bit #(SizeOf #(data_t_)) new_xor);
        bram_a.set_xor (new_xor);
        bram_b.set_xor (new_xor);
    endmethod
    method Action set_pad (Bool set, Bit #(TAdd #(SizeOf #(addr_t_), TLog #(TDiv #(SizeOf #(data_t_), 8)))) start);
        bram_a.set_pad (set, start);
        bram_b.set_pad (set, start);
    endmethod
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

interface Hash_Copy_IFC;
    method Bool is_ready;
endinterface

module mkCopy_Hash_To_BRAM #( Vector #(n_, Bit #(rg_sz_)) v_rg_data
                            , BRAM_PORT #(Bit #(addr_sz_), Bit #(data_sz_)) bram
                            , Bool run
                            , Sink #(Token) snk)
                            (Hash_Copy_IFC)
                            provisos ( Mul #(rg_sz_, rg_in_data_, data_sz_)
                                     , Add#(b__, TAdd#(TLog#(n_), 1), addr_sz_)
                                     , Add#(c__, rg_sz_, data_sz_)
                                     , Mul#(a__, 8, data_sz_)
                                     , Add#(d__, 8, TMul#(a__, 8)));
    Reg #(Bool) rg_started <- mkReg (False);
    Reg #(Bit #(TAdd #(TLog #(n_), 1))) rg_ctr <- mkReg (0);

    rule rl_start (!rg_started);
        if (run) begin
            rg_started <= True;
        end
    endrule
    rule rl_copy (rg_started);
        if (rg_ctr >= fromInteger (valueOf (n_))) begin
            rg_started <= False;
            snk.put (?);
            rg_ctr <= 0;
        end else begin
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
    method is_ready = !rg_started;
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
        rg_ctr <= 0;
    endmethod

    method Action print_state;
        $display ( "    Multi_Push_Stack state -"
                 , "  rg_ctr: ", fshow (rg_ctr)
                 , "  v_rg: ", fshow (readVReg (v_rg)));
    endmethod
endmodule

function Vector #(n_, Reg #(Bit #(TMul #(sz_, 2))))
    fn_merge_vreg (Vector #(TMul #(n_, 2), Reg #(Bit #(sz_))) v_rg_i);

    Vector #(n_, Reg #(Bit #(TMul #(sz_, 2)))) v_rg_o = newVector;
    for (Integer i = 0; i < valueOf (n_); i = i+1) begin
        v_rg_o[i] = interface Reg;
            method Action _write (Bit #(TMul #(sz_, 2)) val);
                v_rg_i[2*i]     <= val[valueOf (sz_) - 1 : 0];
                v_rg_i[2*i + 1] <= val[valueOf (TMul #(sz_, 2)) - 1 : valueOf (sz_)];
            endmethod
            method _read = {v_rg_i[2*i + 1], v_rg_i[2*i]};
        endinterface;
    end
    return v_rg_o;
endfunction

interface VReg_XOR_IFC #(numeric type n_, type data_t_);
    interface Vector #(n_, Reg #(data_t_)) regs;
    method Action set_xor (data_t_ val);
endinterface

module mkVReg_XOR #(Vector #(n_, Reg #(data_t_)) v_rg_i)
                   (VReg_XOR_IFC #(n_, data_t_))
                   provisos ( Bits #(data_t_, data_sz_)
                            , Bitwise#(data_t_)
                            , Literal#(data_t_)
                            , FShow #(data_t_));
    Reg #(data_t_) rg_xor <- mkReg (0);

    Vector #(n_, Reg #(data_t_)) v_rg_o = newVector;
    for (Integer i = 0; i < valueOf (n_); i = i+1) begin
        v_rg_o[i] = interface Reg;
            method Action _write (data_t_ val);
                v_rg_i[i] <= val;
            endmethod
            method data_t_ _read = v_rg_i[i] ^ rg_xor;
        endinterface;
    end

    interface Vector regs = v_rg_o;
    method Action set_xor (data_t_ val);
        $display ("set_xor: ", fshow (val));
        rg_xor <= val;
    endmethod
endmodule

function Vector #(n_, Reg #(data_t_))
    fn_vreg_mux (Vector #(m_, Vector #(n_, Reg #(data_t_))) v_v_rg_i, Bit #(TLog #(m_)) sel);
    return v_v_rg_i[sel];
endfunction



endpackage
