package HWCrypto_Types;

typedef Bit #(0) Token;
typedef enum {
    BUS2BRAM,
    BRAM2BUS
} HWCrypto_Dir deriving (Bits, FShow, Eq);

typedef struct {
    Bit #(m_addr_) bus_addr;
    HWCrypto_Dir dir;
    Bit #(64) len;
} Data_Mover_Req #( numeric type m_addr_
                  ) deriving (Bits, FShow);

typedef struct {
    Bit #(32) len;
    Bool reset_hash;
    Bool pad_one;
    Bool append_len;
} SHA256_Req deriving (Bits, FShow);

// TODO generalise?
typedef struct {
    Bit #(64) data_ptr;
    Bit #(64) data_len;
    Bit #(64) key_ptr;
    Bit #(64) key_len;
    Bit #(64) dest_ptr;
} HWCrypto_Regs deriving (Bits, Eq, FShow);


endpackage
