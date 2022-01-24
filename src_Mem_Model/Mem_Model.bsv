// Copyright (c) 2016-2019 Bluespec, Inc. All Rights Reserved
//-
// RVFI_DII modifications:
//     Copyright (c) 2018 Peter Rugg
//     All rights reserved.
//
//     This software was developed by SRI International and the University of
//     Cambridge Computer Laboratory (Department of Computer Science and
//     Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
//     DARPA SSITH research programme.
//-

package Mem_Model;

// ================================================================
// A simulation model of external DRAM memory.
// Uses a register file to model memory.

// ================================================================
// BSV library imports

import  RegFile      :: *;
import  Vector       :: *;
import  FIFOF        :: *;
import  GetPut       :: *;
import  ClientServer :: *;
import  Memory       :: *;

// ----------------
// BSV additional libs


// ================================================================
// Project imports

import Mem_Controller :: *;

// ================================================================
// Mem Model interface

interface Mem_Model_IFC;
   // The read/write interface
   interface  MemoryServer #(Bits_per_Raw_Mem_Addr, Bits_per_Raw_Mem_Word)  mem_server;
endinterface

typedef 'h4000_0000 Bytes_Per_Mem;
`ifdef RVFI_DII
typedef 'h0000_0000 Zeroed_0_start;
typedef RVFI_DII_Mem_Size Zeroed_0_end;
typedef 'h3f00_0000 Zeroed_1_start;
typedef 'h3fff_ff00 Zeroed_1_end;
`endif

// ================================================================
// Mem Model implementation

(* synthesize *)
module mkMem_Model (Mem_Model_IFC);

   Integer verbosity = 0;    // 0 = quiet; 1 = verbose

   Raw_Mem_Addr alloc_size = fromInteger(valueOf(TDiv#(TMul#(Bytes_Per_Mem,8), Bits_per_Raw_Mem_Word))); //(raw mem words)

`ifdef RVFI_DII
   Raw_Mem_Addr zeroed_0_start = fromInteger(valueOf(TDiv#(Zeroed_0_start, TDiv#(Bits_per_Raw_Mem_Word, 8))));
   Raw_Mem_Addr zeroed_0_end = fromInteger(valueOf(TDiv#(Zeroed_0_end, TDiv#(Bits_per_Raw_Mem_Word, 8))));
   Raw_Mem_Addr zeroed_1_start = fromInteger(valueOf(TDiv#(Zeroed_1_start, TDiv#(Bits_per_Raw_Mem_Word, 8))));
   Raw_Mem_Addr zeroed_1_end = fromInteger(valueOf(TDiv#(Zeroed_1_end, TDiv#(Bits_per_Raw_Mem_Word, 8))));

   RegFile #(Raw_Mem_Addr, Bit #(Bits_per_Raw_Mem_Word)) rf <- mkRegFile (0, alloc_size - 1);
   //zeroes register allows quick resetting of memory. If bit of zeroes is 0 then corresponding entry of rf is 0.
   Reg#(Bit#(TDiv#(TSub#(Zeroed_0_end, Zeroed_0_start), TDiv#(Bits_per_Raw_Mem_Word, 8)))) zeroes_0 <- mkReg(0);
   Reg#(Bit#(TDiv#(TSub#(Zeroed_1_end, Zeroed_1_start), TDiv#(Bits_per_Raw_Mem_Word, 8)))) zeroes_1 <- mkReg(0);
`else
   RegFile #(Raw_Mem_Addr, Bit #(Bits_per_Raw_Mem_Word)) rf <- mkRegFileLoad ("Mem.hex", 0, alloc_size - 1);
`endif

   FIFOF #(MemoryResponse #(Bits_per_Raw_Mem_Word))  f_raw_mem_rsps <- mkFIFOF;

   // ----------------------------------------------------------------
   // INTERFACE

   interface MemoryServer mem_server;
      interface Put request;
	 method Action put (MemoryRequest  #(Bits_per_Raw_Mem_Addr, Bits_per_Raw_Mem_Word) req);
	    if (req.address >= alloc_size) begin
	       $display ("%m: ERROR: Mem_Model.request.put: addr 0x%0h >= size 0x%0h (num raw-mem words)",
			 req.address, alloc_size);
	       $finish (1);    // Assertion failure: address out of bounds
	    end
	    else if (req.write) begin
`ifdef RVFI_DII
            if (req.address >= zeroed_0_start && req.address < zeroed_0_end && zeroes_0[req.address - zeroed_0_start] == 0) begin
                zeroes_0[req.address - zeroed_0_start] <= 1;
            end
            if (req.address >= zeroed_1_start && req.address < zeroed_1_end && zeroes_1[req.address - zeroed_1_start] == 0) begin
                zeroes_1[req.address - zeroed_1_start] <= 1;
            end
`endif
            rf.upd (req.address, req.data);
	       if (verbosity != 0)
		  $display ("%m: Mem_Model write [0x%0h] <= 0x%0h", req.address, req.data);
	    end
	    else begin
	       let x = rf.sub (req.address);
`ifdef RVFI_DII
           $display("req addr: ", fshow(req.address), ", zeroed_0_start: ", fshow(zeroed_0_start), ", zeroed_1_start: ", fshow(zeroed_1_start));
           if (req.address < zeroed_0_end && req.address >= zeroed_0_start && zeroes_0[req.address - zeroed_0_start] == 0) x = 0;
           if (req.address < zeroed_1_end && req.address >= zeroed_1_start && zeroes_1[req.address - zeroed_1_start] == 0) x = 0;
`endif
	       let rsp = MemoryResponse {data: x};
	       f_raw_mem_rsps.enq (rsp);
	       if (verbosity != 0)
		  $display ("%m: Mem_Model read  [0x%0h] => 0x%0h", req.address, x);
	    end
	 endmethod
      endinterface

      interface Get response = toGet (f_raw_mem_rsps);
   endinterface
endmodule

// ================================================================

endpackage
