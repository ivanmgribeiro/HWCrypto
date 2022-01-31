package Test_Top;

import AXI :: *;
import HWCrypto :: *;
import Test_Request_Generator :: *;
import Test_Util :: *;
import Vector :: *;
import Connectable :: *;
import Boot_ROM :: *;
import Mem_Model :: *;
import Mem_Controller :: *;

module mkTest_Top (Empty);

    Vector #(12, Test_Elem) test_seq = newVector;
    test_seq[0]  = Test_Elem {delay:  0, addr:  0, data:  0, is_read: False};
    test_seq[1]  = Test_Elem {delay: 50, addr:  8, data:  11, is_read: False};
    test_seq[2]  = Test_Elem {delay: 50, addr: 16, data:  0, is_read: False};
    test_seq[3]  = Test_Elem {delay: 50, addr: 24, data:  11, is_read: False};
    test_seq[4]  = Test_Elem {delay: 50, addr: 32, data:  'h1000_0001, is_read: False};
    test_seq[5]  = Test_Elem {delay: 50, addr:  0, data:  ?, is_read: True};
    test_seq[6]  = Test_Elem {delay: 50, addr:  8, data:  ?, is_read: True};
    test_seq[7]  = Test_Elem {delay: 50, addr: 16, data:  ?, is_read: True};
    test_seq[8]  = Test_Elem {delay: 50, addr: 24, data:  ?, is_read: True};
    test_seq[9]  = Test_Elem {delay: 50, addr: 32, data:  ?, is_read: True};
    test_seq[10] = Test_Elem {delay: 50, addr: 40, data:  1, is_read: False};
    test_seq[11] = Test_Elem {delay: 5000, addr: 0, data: ?, is_read: True};

    HWCrypto_IFC #(0, 64, 64, 0, 0, 0, 0, 0, 0, 64, 64, 0, 0, 0, 0, 0) hw_crypto <- mkHWCrypto;
    Test_Request_Generator_IFC #(0, 64, 64, 0, 0, 0, 0, 0) test_gen <- mkTest_Request_Generator (test_seq);
    AXI4_Slave #(0, 64, 64, 0, 0, 0, 0, 0) test_slave <- mkPerpetualValueAXI4Slave (?);


    let boot_rom <- mkBoot_ROM;
    AXI4_Shim #(0, 64, 64, 0, 0, 0, 0, 0) brom_deburster <- mkBurstToNoBurst;
    mkConnection (brom_deburster.master, boot_rom.slave);


    let mem_model <- mkMem_Model;
    let mem_controller <- mkMem_Controller;
    AXI4_Shim #(0, 64, 64, 0, 0, 0, 0, 0) mem_deburster <- mkBurstToNoBurst;
    mkConnection (mem_deburster.master, mem_controller.slave);
    mkConnection (mem_controller.to_raw_mem, mem_model.mem_server);

    mkConnection (hw_crypto.axi_s, test_gen.axi_m);

    Vector #(2, AXI4_Slave #(0, 64, 64, 0, 0, 0, 0, 0)) slave_vector = newVector;
    slave_vector[0] = brom_deburster.slave;
    slave_vector[1] = debugAXI4_Slave (mem_deburster.slave, $format ("mem_deburster slave"));

    Vector #(1, AXI4_Master #(0, 64, 64, 0, 0, 0, 0, 0)) master_vector = newVector;
    master_vector[0] = hw_crypto.axi_m;

    function Vector #(2, Bool) fn_route (Bit #(64) addr);
        Vector #(2, Bool) res = replicate (False);
        if (addr >= 'h1000_0000) begin
            res[1] = True;
        end else begin
            res[0] = True;
        end
        return res;
    endfunction
    let bus <- mkAXI4Bus (fn_route, master_vector, slave_vector);


    Reg #(Bool) rg_started <- mkReg (False);
    rule rl_start (!rg_started);
        hw_crypto.set_verbosity (3);
        test_gen.set_verbosity (1);
        mem_controller.set_addr_map ('h1000_0000, 'h2000_0000);
        rg_started <= True;
    endrule
endmodule

endpackage
