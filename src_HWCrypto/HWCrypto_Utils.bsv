package HWCrypto_Utils;

import BRAMCore :: *;
import Vector :: *;

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

endpackage
