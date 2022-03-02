package HWCrypto_Data_Mover;

`define MPARAMS m_id_, m_addr_, m_data_, m_awuser_, m_wuser_, m_buser_, m_aruser_, m_ruser_

import AXI :: *;
import SourceSink :: *;
import HWCrypto_Types :: *;
import BRAMCore :: *;
import Vector :: *;

typedef enum {
    IDLE,
    FETCH_NEXT,
    WAIT_RRESP,
    WRITE_BURST,
    WRITE_LAST,
    WRITE_NEXT,
    ALIGN,
    STEADY,
    FINISH,
    FINISH_READ
} State deriving (Bits, Eq, FShow);

typedef union tagged {
    AXI4_ARFlit #(id_, addr_, aruser_) AR;
    AXI4_AWFlit #(id_, addr_, awuser_) AW;
} AXI4_AFlit #( numeric type id_
              , numeric type addr_
              , numeric type aruser_
              , numeric type awuser_)
              deriving (Bits, FShow);


interface HWCrypto_Data_Mover_IFC #( // bus interface
                                     numeric type m_id_
                                   , numeric type m_addr_
                                   , numeric type m_data_
                                   , numeric type m_awuser_
                                   , numeric type m_wuser_
                                   , numeric type m_buser_
                                   , numeric type m_aruser_
                                   , numeric type m_ruser_
                                   );
    interface AXI4_Master #(`MPARAMS) axi_m;
    method Action request (Data_Mover_Req #(m_addr_) req);
    method Bool is_ready;
    method Action set_verbosity (Bit #(4) new_verb);
endinterface
/* *  Behaviour: *   +  This module will transfer data between the AXI Bus and a BRAM-like
 *      interface
 *   +  The interface for interacting with the module will be a request method
 *      which takes as arguments
 *       +  the bus address
 *       +  the length of data to copy
 *       +  the BRAM address
 *       +  the direction of copy (BRAM->Bus or Bus->BRAM)
 *      
 *      
 *      
 *      
 *  First, we need to align the address so we can fetch bigger things (AXI4
 *  means that our requests must always be size-aligned
 */
module mkHWCrypto_Data_Mover #( Vector #(8, Reg #(Bit #(64))) v_rg_regs
                              , Sink #(Token) snk)
                               (HWCrypto_Data_Mover_IFC #(`MPARAMS))
                               provisos ( Add#(a__, TLog#(TAdd#(1, TLog#(TDiv#(m_data_, 8)))), 3)
                                        , Add#(b__, 10, m_addr_)
                                        , Add#(c__, TLog#(TDiv#(m_data_, 8)), m_addr_)
                                        // TODO relax this?
                                        , Add#(0, 64, m_data_)
                                        , Add#(f__, 3, TLog#(TDiv#(m_data_, 8)))
                                        , Add#(g__, TLog#(TDiv#(m_data_, 8)), 64)

                                        //, Add#(h__, 1, bram_be_)
                                        //, Mul#(bram_be_, 8, m_data_)
                                        //, Add#(i__, 8, TMul#(bram_be_, 8))
                                        , Add#(m_data_, j__, TMul#(m_data_, 2))
                                        //, Add#(d__, TMul#(bram_be_, 8), TMul#(m_data_, 2))
                                        //, Div#(m_data_, 8, bram_be_)
                                        //, Mul#(bram_be_, 8, m_data_)

                                        , Mul#(TDiv#(m_data_, 8), 8, m_data_)
                                        , Add#(d__, 8, TMul#(TDiv#(m_data_, 8), 8))
                                        , Add#(i__, TMul#(TDiv#(m_data_, 8), 8), 128)
                                        , Add#(h__, 3, m_addr_)
                                        );
    Wire #(Bool) dw_cycle_counter_reset <- mkDWire (False);
    Reg #(Bit #(64)) rg_cycle_counter <- mkReg (0);
    Reg #(Bit #(m_addr_)) rg_bus_addr <- mkRegU;
    // normally, the bram address is a bram word address (ie it addresses which
    // bram-sized word you are accessing).
    // this address is instead a byte address
    // the address of the byte in BRAM currently being accessed
    Reg #(Bit #(TAdd #(3, TLog #(TDiv #(64, 8))))) rg_int_addr_b <- mkRegU;
    Reg #(HWCrypto_Dir) rg_dir <- mkRegU;
    // TODO make this 64 general
    Reg #(Bit #(64)) rg_len <- mkRegU;
    Reg #(Bit #(64)) rg_bytes_left <- mkRegU;
    Reg #(State) rg_state <- mkReg (IDLE);
    Reg #(AXI4_Size) rg_last_req_size <- mkRegU;
    Reg #(AXI4_Len) rg_flits_left <- mkRegU;
    Reg #(Bit #(4)) rg_verbosity <- mkReg (0);
    Reg #(Bit #(64)) rg_last_data <- mkRegU;
    let shim <- mkAXI4ShimFF;
    let ugshim_slave <- toUnguarded_AXI4_Slave (shim.slave);


    // returns the maximum AXI len you can request while still staying within a 4KB boundary
    // returns len up to 7 (meaning maximum 8 flits)
    // assumes that the address is size-aligned
    // (ie if the size is 64bits/8bytes then addr[2:0] is 0
    // For now, assume the size of each word being copied is 32 bits
    // 4KB boundary corresponds to the bottom 12 bits
    // ie if the bottom 12 bits are 0, the request is 4KB aligned
    function Bit #(3) fn_arlen_from_4k_boundary (Bit #(m_addr_) addr);
        let ones = ~0;
        // this is where the 32-bit assumption is made
        // We take the bottom 12 bits, and of those we ignore the bottom 2 or 3 bits (depending
        // on whether we're doing 32bit or 64bit accesses) because we assume the address is
        // size-aligned
        Bit #(TSub #(12, TLog #(TDiv #(32, 8)))) addr_lsb = truncate (addr >> valueOf (TLog #(TDiv #(32, 8))));

        // "ones" represents the last word that we could write without crossing
        // the 4KB boundary
        // Here we find out how far away we are from that word address
        Bit #(TSub #(12, TLog #(TDiv #(32, 8)))) sub = ones - addr_lsb;

        let retval = 3'b111;
        if (sub > zeroExtend (3'b111)) begin
            // We are more than 8 words away from the boundary, so we can write 8 words
            retval = 3'b111;
        end else begin
            // We are fewer than 8 words away from the boundary
            retval = truncate (sub);
        end
        return retval;
    endfunction


    // Find the index of the lowest (closest to LSB) 1 in the input
    // and return it.
    // If the input is all 0s, returns 0.
    function Bit #(TLog #(n_)) fn_lowest_one (Bit #(n_) in);
        Bit #(TLog #(n_)) pos = 0;
        for (Integer i = valueOf (n_) - 1; i >= 0; i = i-1) begin
            if (in[i] == 1) begin
                pos = fromInteger (i);
            end
        end
        return pos;
    endfunction

    // Find the maximum size that we can request based on the address
    // alignment
    function AXI4_Size fn_max_size (Bit #(n_) addr)
        provisos (Add#(e__, TLog#(TDiv#(m_data_, 8)), n_));
        // Select how many bits we need from the LSBs to check alignment
        // Maximum alignment is bus-width-aligned
        Bit #(TLog #(TDiv #(m_data_, 8))) addr_lsbs = truncate (addr);
        // Find the index of the lowest (closest to LSB) 1 in the LSBs
        // Concatenate a 1 at the top to ensure that there is at least one 1
        let pos = fn_lowest_one ({1'b1, addr_lsbs});
        // the value we get is the same as the AXI4_Size we need
        return unpack (zeroExtend (pos));
    endfunction

    // returns the number of bytes required to make the next request
    // bus-width-aligned
    function Bit #(TLog #(TDiv #(m_data_, 8))) fn_bytes_to_align (Bit #(m_addr_) addr);
        Bit #(TLog #(TDiv #(m_data_, 8))) addr_lsb = truncate (addr);
        Int #(TLog #(TDiv #(m_data_, 8))) int_lsb = unpack (addr_lsb);
        return pack (-int_lsb);
    endfunction

    // convert size to byte-enable signal
    function Bit #(n_) fn_size_to_be (AXI4_Size size);
        Bit #(n_) ones = ~0;
        let shamt = 1 << pack (size);
        return truncate (~(ones << shamt));
    endfunction

    function Bit #(TMul #(n_, 8)) fn_byte_to_bit_enable (Bit #(n_) byte_enable)
        provisos (Add#(z__, 8, TMul#(n_, 8)));
        Bit #(TMul #(n_, 8)) out = 0;
        for (Integer i = 0; i < valueOf (n_); i = i+1) begin
            Bit #(8) cur_byte = byte_enable[i] == 1'b1 ? ~0 : 0;
            out[i*8+7:i*8] = cur_byte;
            //out[i*8+7:i*8] = byte_enable[i] == 1'b1 ? ~0 : 0;
        end
        return out;
    endfunction

    //Reg #(Bit #(m_addr_)) rg_ctr <- mkReg (0);
    //rule rl_test;
    //    rg_ctr <= rg_ctr + 1;
    //    let b_to_a = fn_bytes_to_align (rg_ctr);
    //    let s1 = truncate (rg_ctr);
    //    $display ( "rg_ctr: ", fshow (rg_ctr)
    //             , " fn_bytes_to_align: ", fshow (b_to_a)
    //             , " sum: ", fshow (b_to_a + s1));
    //endrule


    rule rl_counter_incr;
        if (dw_cycle_counter_reset) begin
            rg_cycle_counter <= 0;
        end else begin
            rg_cycle_counter <= rg_cycle_counter + 1;
        end
    endrule


    // set 1: get bus-width aligned.
    //  *  need to find out how far off we are from being bus-width aligned
    //  *  once we know that, find out what the biggest size we can request is
    //  *  once we know that, make max-sized requests until we know that
    // invariant:
    //  *  if the bus is 64b wide, then we need a maximum of 7
    //     bytes in order to get aligned, which we can satisfy in 1 burst
    // issues:
    //  *  if our request is smaller than what is required for bus-width
    //     alignment, then we can't do this but we just request as bytes?
    //  *  if our request is small enough it might not make sense to even
    //     make any bus-sized requests

    // if size <= 8 bytes
    //  *  don't bother aligning, just read with the size as big as possible
    //     while still being aligned
    //     (ie if byte-aligned, do n single-byte reads, if 2byte aligned, do
    //     n/2 2byte reads etc)



    rule rl_handle_write (rg_state == WRITE_BURST && ugshim_slave.w.canPut && rg_dir == BRAM2BUS);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover rl_handle_write");
        end
        //let data = bram.read;
        Bit #(TLog #(TDiv #(64, 8))) bus_addr_lsb = truncate (rg_bus_addr);
        Bit #(TLog #(TDiv #(64, 8))) int_addr_lsb = truncate (rg_int_addr_b);
        Bit #(3) int_addr = truncate (rg_int_addr_b >> 3);

        let bytes_accessed = 1 << pack (rg_last_req_size);
        let int_end_addr = {1'b0, int_addr_lsb} + bytes_accessed;
        Bit #(TLog #(TDiv #(64, 8))) int_end_addr_lsb = truncate (int_end_addr);
        Bit #(1)                     int_end_addr_msb = truncateLSB (int_end_addr);
        let straddles_int_word = int_end_addr_msb==1'b1 && int_end_addr_lsb!=0;

        let data_lower = v_rg_regs[int_addr];
        let data_upper = straddles_int_word ? v_rg_regs[int_addr + 1] : 0;
        let data_rs = {data_upper, data_lower} >> {int_addr_lsb, 3'b000};

        let data_ls = data_rs << {bus_addr_lsb, 3'b000};


        Bit #(TDiv #(m_data_, 8)) be_lsb = fn_size_to_be (rg_last_req_size);
        let be_bus = be_lsb << bus_addr_lsb;
        let be_bit = fn_byte_to_bit_enable (be_bus);
        let data_masked = (truncate (data_ls) & be_bit);

        //Bit #(64) addr = truncate (new_int_addr_last >> 3);
        //if (rg_verbosity > 1) begin
        //    $display ( "    internal request data  -  addr: ", fshow (addr));
        //end
        //bram.put (False, addr, ?);

        let new_flits_left = rg_flits_left - 1;
        let new_bus_addr = rg_bus_addr + bytes_accessed;
        let new_bytes_left = rg_bytes_left - bytes_accessed;
        let new_int_addr_b = rg_int_addr_b + bytes_accessed;
        // TODO this is wrong
        rg_flits_left <= new_flits_left;
        rg_bus_addr <= new_bus_addr;
        rg_int_addr_b <= new_int_addr_b;
        rg_bytes_left <= new_bytes_left;

        if (rg_verbosity > 1) begin
            $display ( "    bytes_left: ", fshow (rg_bytes_left)
                     , "  new_bytes_left: ", fshow (new_bytes_left)
                     , "  new_flits_left: ", fshow (new_flits_left)
                     , "  new_bus_addr: ", fshow (new_bus_addr)
                     , "  rg_int_addr_b: ", fshow (rg_int_addr_b)
                     , "  new_int_addr_b: ", fshow (new_int_addr_b)
                     , "  straddles_int_word: ", fshow (straddles_int_word));
            //$display ("    rg_last_data: ", fshow (rg_last_data), "  bram.read: ", fshow (bram.read), "  data_ls: ", fshow (data_ls), "  data_rs: ", fshow (data_rs));
            $display ("    rg_last_data: ", fshow (rg_last_data), "  data_ls: ", fshow (data_ls), "  data_rs: ", fshow (data_rs));
            $display ( "    be_bus: ", fshow (be_bus)
                     , "  be_bit: ", fshow (be_bit)
                     , "  data_masked: ", fshow (data_masked));
        end

        AXI4_WFlit #(m_data_, m_wuser_) wflit = AXI4_WFlit { wdata: data_masked
                                                           , wstrb: be_bus
                                                           , wlast: rg_flits_left == 0
                                                           , wuser: 0
                                                           };
        ugshim_slave.w.put (wflit);
        if (rg_verbosity > 0) begin
            $display ("    flit: ", fshow (wflit));
        end
        if (rg_flits_left == 0) begin
            if (new_bytes_left == 0) begin
                $display ("    finished");
                $display ("    cycle counter: ", fshow (rg_cycle_counter));
                rg_state <= IDLE;
                snk.put (?);
            end else begin
                // need to write the next AWFlit if needed
                rg_state <= WRITE_NEXT;
            end
        end
    endrule

    rule rl_drop_bresp (ugshim_slave.b.canPeek);
        ugshim_slave.b.drop;
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover rl_drop_bresp");
            $display ("    flit: ", fshow (ugshim_slave.b.peek));
        end
    endrule

    rule rl_handle_next_write (rg_state == WRITE_NEXT
                               && ugshim_slave.aw.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover rl_handle_next_write");
        end
        AXI4_AWFlit #(m_id_, m_addr_, m_awuser_) awflit = defaultValue;
        awflit.awid = 0;
        awflit.awaddr = rg_bus_addr;
        if (rg_bytes_left >= fromInteger (valueOf (TDiv #(m_data_, 8)))) begin
            // we can still make bus-width-aligned requests because the amount
            // of data left is enough to support that
            awflit.awsize = fromInteger (valueOf (TDiv #(m_data_, 8)));
            // the tag controller forces bursts with 8 or fewer flits
            // TODO replace TLog 3 with something cleaner
            let shamt = fromInteger (valueOf (TLog #(TDiv #(m_data_, 8))));
            let len = min (7, ((rg_bytes_left >> shamt) - 1));
            awflit.awlen = truncate (len);
            if (rg_verbosity > 0) begin
                $display ("    making big transaction");
            end
        end else begin
            // this is the last burst request
            // make the maximum-sized request we can make
            let max_req_size = fn_max_size (rg_bytes_left);
            awflit.awsize = max_req_size;
            Bit #(TLog #(8)) len = truncate ((rg_bytes_left >> pack (max_req_size)) - 1);
            awflit.awlen = zeroExtend (len);
            if (rg_verbosity > 0) begin
                $display ("    making small transaction");
            end
        end

        ugshim_slave.aw.put (awflit);
        rg_last_req_size <= awflit.awsize;
        rg_flits_left <= awflit.awlen;

        //bram.put (False, truncateLSB (addr), ?);

        rg_state <= WRITE_BURST;

        if (rg_verbosity > 0) begin
            $display ("    flit: ", fshow (awflit));
        end
    endrule


    rule rl_handle_rresp (rg_state == WAIT_RRESP && ugshim_slave.r.canPeek && rg_dir == BUS2BRAM);
        let rflit = ugshim_slave.r.peek;
        ugshim_slave.r.drop;
        let bytes_read = 1 << pack (rg_last_req_size);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover rl_handle_rresp");
            $display ("    flit: ", fshow (rflit));
        end

        // need to combine data from last read with data from this read
        // bram address tells us where we need to start writing
        // on the first write, we fill at most one BRAM word
        // the next write might need to have the same address (writing a
        // different part of the word)
        // example: if we are reading in single bytes (to get the bus address
        // aligned) then we only write single bytes into the BRAM


        // input data right-shifted to low bits
        Bit #(TLog #(TDiv #(64, 8))) bus_addr_lsb = truncate (rg_bus_addr);
        Bit #(64) data_rs = rflit.rdata >> {bus_addr_lsb, 3'b000};

        // data now needs to be left-shifted to the correct place for writing
        // into BRAMs
        // we want to keep the bits that would have got shifted away, so we
        // double the width of data_ls
        Bit #(TLog #(TDiv #(64, 8))) int_addr_lsb = truncate (rg_int_addr_b);
        Bit #(TMul #(64, 2)) data_ls = zeroExtend (data_rs) << {int_addr_lsb, 3'b000};

        let int_end_addr = {1'b0, int_addr_lsb} + bytes_read;
        Bit #(TLog #(TDiv #(64, 8))) int_end_addr_lsb = truncate (int_end_addr);
        Bit #(1)                     int_end_addr_msb = truncateLSB (int_end_addr);
        let straddles_int_word = int_end_addr_msb==1'b1 && int_end_addr_lsb!=0;

        Bit #(8)  be_lsb = fn_size_to_be (rg_last_req_size);
        Bit #(16) be_int = zeroExtend (be_lsb) << int_addr_lsb;
        let be_bit = fn_byte_to_bit_enable (be_int);
        let data_masked = data_ls & be_bit;
        Bit #(TLog #(8)) int_addr = truncate (rg_int_addr_b >> 3);
        Bit #(64) data_masked_lower = truncate (data_masked) | (~(truncate (be_bit)) & v_rg_regs[int_addr]);
        Bit #(64) data_masked_upper = truncateLSB (data_masked) | (~(truncateLSB (be_bit)) & v_rg_regs[int_addr + 1]);

        //let new_last_data = data_masked;
        //if (straddles_int_word) begin
        //    new_last_data = truncateLSB (data_ls);
        //end else begin
        //    // add in the data we've just received to the register so that it
        //    // will be re-written again once we get to a full-width word
        //    new_last_data = data_masked;
        //end
        //rg_last_data <= new_last_data;


        // generate the byte-enable from the size and shift it to the correct
        // place for the BRAM write
        //let be = be_lsb << int_addr_lsb;

        // now need to get the previous write data and make sure it gets
        // written in as well
        //let prev_data_rs

        if (rg_verbosity > 1) begin
            $display ( "    internal request data  -  addr: ", fshow (int_addr)
                     , "  be_bit:  ", fshow (be_bit)
                     , "  be_lsb:  ", fshow (be_lsb)
                     , "  data_masked: ", fshow (data_masked)
                     , "  data_masked_lower: ", fshow (data_masked_lower)
                     , "  data_masked_upper: ", fshow (data_masked_upper)
                     , "  straddles_int_word: ", fshow (straddles_int_word));
        end
        //bram.put (True, addr, data);
        v_rg_regs[int_addr] <= data_masked_lower;
        if (straddles_int_word) begin
            v_rg_regs[int_addr + 1] <= data_masked_upper;
        end

        let new_flits_left = rg_flits_left - 1;
        let new_bus_addr = rg_bus_addr + bytes_read;
        let new_bytes_left = rg_bytes_left - bytes_read;
        // TODO this is wrong
        let new_int_addr = rg_int_addr_b + bytes_read;
        rg_flits_left <= new_flits_left;
        rg_bus_addr <= new_bus_addr;
        rg_int_addr_b <= new_int_addr;
        rg_bytes_left <= new_bytes_left;

        if (rg_verbosity > 1) begin
            $display ( "    bytes_left: ", fshow (rg_bytes_left)
                     , "  new_bytes_left: ", fshow (new_bytes_left)
                     , "  new_flits_left: ", fshow (new_flits_left)
                     , "  new_bus_addr: ", fshow (new_bus_addr)
                     , "  new_int_addr: ", fshow (new_int_addr));
        end

        if (rflit.rlast) begin
            // this is the last flit
            if (rg_flits_left != 0) begin
                $display ("%m HWCrypto ERROR: rlast is true but we expected more flits");
                $display ("    rflit: ", fshow (rflit));
                $display ("    rg_flits_left: ", fshow (rg_flits_left));
            end
            if (new_bytes_left == 0) begin
                if (rg_len == 64) begin
                    rg_state <= IDLE;
                    snk.put (?);
                    $display ("    fetch finished; going to IDLE");
                end else begin
                    rg_state <= FINISH_READ;
                    $display ("    fetch finishing; still need to zero the rest; going to FINISH_READ");
                end
            end else begin
                rg_state <= FETCH_NEXT;
            end
        end
    endrule

    rule rl_finish_read (rg_state == FINISH_READ);
        if (rg_verbosity > 0) begin
            $display ("HWCrypto DataMover rl_finish_read");
            $display ("    cycle counter: ", fshow (rg_cycle_counter));
        end
        Bit #(TLog #(8)) rgindex = truncate (rg_len >> 3);
        Bit #(3) len_lsb = truncate (rg_len);
        Bit #(64) mask = ~(~0 << {len_lsb, 3'b000});
        v_rg_regs[rgindex] <= v_rg_regs[rgindex] & mask;
        for (Integer i = 0; i < 8; i = i+1) begin
            if (fromInteger (i) > rgindex) begin
                v_rg_regs[i] <= 0;
            end
        end
        rg_state <= IDLE;
        snk.put (?);
    endrule

    // This rule assumes that the address in rg_bus_addr is bus-width-aligned
    // and will make as many bus-width requests as it can without overrunning
    rule rl_fetch_next (rg_state == FETCH_NEXT
                        && ugshim_slave.ar.canPut);
        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover rl_fetch_next");
        end
        AXI4_ARFlit #(m_id_, m_addr_, m_aruser_) arflit = defaultValue;
        arflit.arid = 0;
        arflit.araddr = rg_bus_addr;
        if (rg_bytes_left >= fromInteger (valueOf (TDiv #(m_data_, 8)))) begin
            // we can still make bus-width-aligned requests because the amount
            // of data left is enough to support that
            arflit.arsize = fromInteger (valueOf (TDiv #(m_data_, 8)));
            // the tag controller forces bursts with 8 or fewer flits
            // TODO replace TLog 3 with something cleaner
            let shamt = fromInteger (valueOf (TLog #(TDiv #(m_data_, 8))));
            let len = min (7, ((rg_bytes_left >> shamt) - 1));
            arflit.arlen = truncate (len);
            if (rg_verbosity > 0) begin
                $display ("    making big transaction");
            end
        end else begin
            // this is the last read request
            // make the maximum-sized request we can make
            let max_req_size = fn_max_size (rg_bytes_left);
            arflit.arsize = max_req_size;
            Bit #(TLog #(8)) len = truncate ((rg_bytes_left >> pack (max_req_size)) - 1);
            arflit.arlen = zeroExtend (len);
            if (rg_verbosity > 0) begin
                $display ("    making small transaction");
            end
        end

        ugshim_slave.ar.put (arflit);
        rg_last_req_size <= arflit.arsize;
        rg_flits_left <= arflit.arlen;

        rg_state <= WAIT_RRESP;

        if (rg_verbosity > 0) begin
            $display ("    flit: ", fshow (arflit));
        end
    endrule




    method Action request (Data_Mover_Req #(m_addr_) req)
                          if (rg_state == IDLE);
        let bus_addr  = req.bus_addr;
        let len       = req.len;
        let dir       = req.dir;

        let b_to_align = fn_bytes_to_align (bus_addr);

        // maximum request size allowed by address alignment
        AXI4_Size max_addr_req_size = fn_max_size (bus_addr);
        // maximum request size allowed by length alignment
        AXI4_Size max_len_req_size = fn_max_size (len);
        // maximum request size allowed to make address bus-width-aligned
        AXI4_Size max_align_req_size = fn_max_size (b_to_align);

        // the maximum size if we are doing the full request in one burst
        AXI4_Size max_req_size_full = min (max_len_req_size, max_addr_req_size);
        // the maximum size if we are aligning the address of the next burst
        AXI4_Size max_req_size_to_align = min (max_align_req_size, max_addr_req_size);

        // requests have a hard maximum length of 8 enforced by the tag
        // controller
        // request length based on input len (we are doing the full request)
        Bit #(TLog #(8)) req_len_full = truncate ((len >> pack (max_req_size_full)) - 1);
        // request length based on number of bytes required to align
        Bit #(TLog #(8)) req_len_to_align = truncate ((b_to_align >> pack (max_req_size_to_align)) - 1);
        // request length based on making max-size (ie bus-width) requests
        Bit #(TLog #(8)) req_len_max = truncate ((len >> pack (max_addr_req_size)) - 1);

        AXI4_Len flit_len = ?;
        AXI4_Size flit_size = ?;

        // TODO replace 8 (max req len, decided by AXI tag controller)
        // if length is short enough, make a single request that finish the
        // request
        Bit #(64) len_cmp = 64'h8 << pack (max_req_size_full);
        if (!(len > len_cmp)) begin
            // we can make one single burst request with size max_req_size
            flit_len = zeroExtend (req_len_full);
            flit_size = max_req_size_full;
        end else if (b_to_align == 0) begin
            // we are already aligned, and can't fulfill the entire request
            // with only one burst; make the biggest request we can
            flit_len = zeroExtend (req_len_max);
            flit_size = max_addr_req_size;
        end else begin
            // we need more than one burst to fulfill the request
            // the first burst request we make is to align the start address of
            // the next burst
            flit_len = zeroExtend (req_len_to_align);
            flit_size = max_req_size_to_align;
        end

        if (rg_verbosity > 0) begin
            $display ("%m HWCrypto DataMover request");
            $display ( "    request parameters -"
                     , "  bus_addr: ", fshow (bus_addr)
                     , "  dir: ", fshow (dir)
                     , "  len: ", fshow (len));
            //$display ("    flit: ", fshow (aflit));
        end
        if (rg_verbosity > 1) begin
            $display ( "    internal vals -"
                     , "  b_to_align: ", fshow (b_to_align)
                     , "  max_addr_req_size: ", fshow (max_addr_req_size)
                     , "  max_len_req_size: ", fshow (max_len_req_size)
                     , "  max_align_req_size: ", fshow (max_align_req_size)
                     , "  max_req_size_full: ", fshow (max_req_size_full)
                     , "  max_req_size_to_align: ", fshow (max_req_size_to_align)
                     , "  req_len_full: ", fshow (req_len_full)
                     , "  req_len_to_align: ", fshow (req_len_to_align));
        end
        if (len != 0 && (zeroExtend (flit_len) + 1) << pack (flit_size) > len) begin
            $display ("%m HWCrypto ERROR: OVERREAD");
        end

        if (len != 0) begin
            if (dir == BUS2BRAM) begin
                AXI4_ARFlit #(m_id_, m_addr_, m_aruser_) arflit = defaultValue;
                arflit.arid = 0;
                arflit.araddr = bus_addr;
                arflit.arlen = flit_len;
                arflit.arsize = flit_size;
                ugshim_slave.ar.put (arflit);
                $display ("    arflit: ", fshow (arflit));
            end else begin
                AXI4_AWFlit #(m_id_, m_addr_, m_awuser_) awflit = defaultValue;
                awflit.awid = 0;
                awflit.awaddr = bus_addr;
                awflit.awlen = flit_len;
                awflit.awsize = flit_size;
                ugshim_slave.aw.put (awflit);
                $display ("    awflit: ", fshow (awflit));
            end
        end

        rg_bus_addr <= bus_addr;
        rg_last_req_size <= flit_size;
        rg_flits_left <= flit_len;
        rg_int_addr_b <= 0;
        rg_dir <= dir;
        rg_len <= len;
        rg_bytes_left <= len;
        rg_state <= len == 0 ? dir == BUS2BRAM ? FINISH_READ : IDLE
                             : dir == BUS2BRAM ? WAIT_RRESP : WRITE_BURST;
        dw_cycle_counter_reset <= True;
    endmethod

    method Bool is_ready = rg_state == IDLE;

    interface axi_m = shim.master;

    method Action set_verbosity (Bit #(4) new_verb);
        rg_verbosity <= new_verb;
    endmethod
 endmodule

endpackage
