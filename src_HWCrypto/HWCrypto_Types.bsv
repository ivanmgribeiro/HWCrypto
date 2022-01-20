package HWCrypto_Types;

typedef Bit #(0) Token;
typedef enum {
    BUS2BRAM,
    BRAM2BUS
} HWCrypto_Dir deriving (Bits, FShow, Eq);

endpackage
