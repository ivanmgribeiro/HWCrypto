package Test_Top;

import AXI :: *;
import HWCrypto :: *;
import Test_Request_Generator :: *;
import Test_Util :: *;
import Vector :: *;
import Connectable :: *;
import Boot_ROM :: *;

module mkTest_Top (Empty);

    Vector #(12, Test_Elem) test_seq = newVector;
    test_seq[0]  = Test_Elem {delay:  0, addr:  0, data:  1, is_read: False};
    test_seq[1]  = Test_Elem {delay: 50, addr:  8, data: 32, is_read: False};
    test_seq[2]  = Test_Elem {delay: 50, addr: 16, data:  4, is_read: False};
    test_seq[3]  = Test_Elem {delay: 50, addr: 24, data:  4, is_read: False};
    test_seq[4]  = Test_Elem {delay: 50, addr: 32, data:  4, is_read: False};
    test_seq[5]  = Test_Elem {delay: 50, addr:  0, data:  ?, is_read: True};
    test_seq[6]  = Test_Elem {delay: 50, addr:  8, data:  ?, is_read: True};
    test_seq[7]  = Test_Elem {delay: 50, addr: 16, data:  ?, is_read: True};
    test_seq[8]  = Test_Elem {delay: 50, addr: 24, data:  ?, is_read: True};
    test_seq[9]  = Test_Elem {delay: 50, addr: 32, data:  ?, is_read: True};
    test_seq[10] = Test_Elem {delay: 50, addr: 40, data:  1, is_read: False};
    test_seq[11] = Test_Elem {delay: 500, addr: 0, data: ?, is_read: True};

    HWCrypto_IFC #(0, 64, 64, 0, 0, 0, 0, 0, 0, 64, 64, 0, 0, 0, 0, 0) hw_crypto <- mkHWCrypto;
    Test_Request_Generator_IFC #(0, 64, 64, 0, 0, 0, 0, 0) test_gen <- mkTest_Request_Generator (test_seq);
    AXI4_Slave #(0, 64, 64, 0, 0, 0, 0, 0) test_slave <- mkPerpetualValueAXI4Slave (?);
    AXI4_Shim #(0, 64, 64, 0, 0, 0, 0, 0) deburster <- mkBurstToNoBurst;
    let boot_rom <- mkBoot_ROM;
    mkConnection (deburster.master, boot_rom.slave);

    mkConnection (hw_crypto.axi_s, test_gen.axi_m);
    mkConnection (hw_crypto.axi_m, deburster.slave);

    Reg #(Bool) rg_started <- mkReg (False);
    rule rl_start (!rg_started);
        hw_crypto.set_verbosity (3);
        test_gen.set_verbosity (1);
    endrule
endmodule

endpackage
