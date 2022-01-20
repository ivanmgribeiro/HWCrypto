// Copyright (c) 2016-2020 Bluespec, Inc. All Rights Reserved

//-
// AXI (user fields) modifications:
//     Copyright (c) 2019 Alexandre Joannou
//     Copyright (c) 2019 Peter Rugg
//     Copyright (c) 2019 Jonathan Woodruff
//     All rights reserved.
//
//     This software was developed by SRI International and the University of
//     Cambridge Computer Laboratory (Department of Computer Science and
//     Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
//     DARPA SSITH research programme.
//-

package Boot_ROM;

// ================================================================
// This package implements a slave IP that is a RISC-V boot ROM of
// 1024 32b locations.
// - Ignores all writes, always responsing OKAY
// - Assumes all reads are 4-byte aligned requests for 4-bytes

// ================================================================

export Boot_ROM_IFC (..), mkBoot_ROM;

// ================================================================
// BSV library imports

import ConfigReg :: *;

// ----------------
// BSV additional libs

import AXI4       :: *;
import SourceSink :: *;

// ================================================================
// Project imports


// ================================================================
// Include the auto-generated BSV-include file with the ROM function

`include  "fn_read_ROM_RV64.bsvi"

// ================================================================
// Interface

interface Boot_ROM_IFC;
   // Main Fabric Reqs/Rsps
   interface AXI4_Slave #(0, 64, 64, 0, 0, 0, 0, 0) slave;
endinterface

// ================================================================
// Some local help-functions

function Bool fn_addr_is_aligned (Bit #(64) addr, AXI4_Size arsize);
   if      (arsize == 1)  return True;
   else if (arsize == 2)  return (addr [0] == 1'b_0);
   else if (arsize == 4)  return (addr [1:0] == 2'b_00);
   else if (arsize == 8)  return (addr [2:0] == 3'b_000);
   else return False;
endfunction

function Bool fn_addr_is_in_range (Bit #(64) base, Bit #(64) addr, Bit #(64) lim);
   return ((base <= addr) && (addr < lim));
endfunction

function Bool fn_addr_is_ok (Bit #(64) base, Bit #(64) addr, Bit #(64) lim, AXI4_Size arsize);
   return (   fn_addr_is_aligned (addr, arsize)
	   && fn_addr_is_in_range (base, addr, lim));
endfunction

// ================================================================

(* synthesize *)
module mkBoot_ROM (Boot_ROM_IFC);

   // Verbosity: 0: quiet; 1: reads/writes
   Integer verbosity = 0;

   Reg #(Bool) rg_module_ready <- mkReg (True);

   Reg #(Bit #(64))  rg_addr_base <- mkReg (0);
   Reg #(Bit #(64))  rg_addr_lim  <- mkReg ('hffff_ffff_ffff_ffff);

   // ----------------
   // Connector to fabric

   let slavePortShim <- mkAXI4ShimFF;

   // ----------------

   // ================================================================
   // BEHAVIOR

   // ----------------------------------------------------------------
   // Handle fabric read requests

   rule rl_process_rd_req (rg_module_ready);
      slavePortShim.master.ar.drop;
      let rda = slavePortShim.master.ar.peek;

      AXI4_Resp  rresp  = OKAY;
      Bit #(64)  data64 = 0;

      if (! fn_addr_is_ok (rg_addr_base, rda.araddr, rg_addr_lim, rda.arsize)) begin
	 rresp = SLVERR;
	 $display ("%m: ERROR: Boot_ROM.rl_process_rd_req: unrecognized or misaligned addr");
	 $display ("    ", fshow (rda));
      end
      else begin
	 // Byte offset
	 let byte_offset = rda.araddr - rg_addr_base;
	 let rom_addr_0 = (byte_offset & (~ 'b_111));
	 Bit #(32) d0 = fn_read_ROM_0 (rom_addr_0);
	 let rom_addr_4 = (rom_addr_0 | 'b_100);
	 Bit #(32) d4 = fn_read_ROM_4 (rom_addr_4);
	 data64 = { d4, d0 };
      end

      Bit #(64) rdata  = truncate (data64);
      AXI4_RFlit#(0, 64, 0) rdr = AXI4_RFlit {rid:   rda.arid,
			      rdata: rdata,
			      rresp: rresp,
			      rlast: True,
			      ruser: 0};
      slavePortShim.master.r.put(rdr);

      if (verbosity > 0) begin
	 $display ("%m: Boot_ROM.rl_process_rd_req: ");
	 $display ("        ", fshow (rda));
	 $display ("     => ", fshow (rdr));
      end
   endrule

   // ----------------------------------------------------------------
   // Handle fabric write requests: ignore all of them (this is a ROM)

   rule rl_process_wr_req (rg_module_ready);
      let wra <- get(slavePortShim.master.aw);
      let wrd <- get(slavePortShim.master.w);

      AXI4_Resp  bresp = OKAY;
      if (! fn_addr_is_ok (rg_addr_base, wra.awaddr, rg_addr_lim, wra.awsize)) begin
	 bresp = SLVERR;
	 $display ("%m: ERROR: Boot_ROM.rl_process_wr_req: unrecognized or misaligned addr");
	 $display ("    ", fshow (wra));
      end

      AXI4_BFlit#(0, 0) wrr = AXI4_BFlit {bid:   wra.awid,
			                       bresp: bresp,
			                       buser: 0};
      slavePortShim.master.b.put(wrr);

      if (verbosity > 0) begin
	 $display ("%m: Boot_ROM.rl_process_wr_req; ignoring all writes");
	 $display ("        ", fshow (wra));
	 $display ("        ", fshow (wrd));
	 $display ("     => ", fshow (wrr));
      end
   endrule

   // Main Fabric Reqs/Rsps
   interface  slave = slavePortShim.slave;
endmodule

// ================================================================

endpackage
