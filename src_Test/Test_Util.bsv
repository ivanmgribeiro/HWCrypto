package Test_Util;

// TODO generalise away 64
typedef struct {
    Bit #(64) delay;
    Bit #(64) addr;
    Bit #(64) data; // TODO make this the expected value when reading?
    Bool is_read;
} Test_Elem deriving (Bits, FShow);

endpackage
