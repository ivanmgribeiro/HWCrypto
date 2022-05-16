package HWCrypto_Types;

typedef Bit #(0) Token;
typedef enum {
    ERROR,
    OKAY
} HWCrypto_Err deriving (Bits, FShow, Eq);
typedef enum {
    BUS2BRAM,
    BRAM2BUS
} HWCrypto_Dir deriving (Bits, FShow, Eq);

typedef struct {
    Bit #(m_addr_) bus_addr;
    Bit #(bram_addr_sz_) bram_addr;
    HWCrypto_Dir dir;
    Bit #(64) len;
} Data_Mover_Req #( numeric type m_addr_
                  , numeric type bram_addr_sz_
                  ) deriving (Bits, FShow);

typedef struct {
    Bit #(bram_addr_sz_) bram_addr;
    Bit #(32) len;
    Bool reset_hash;
    Bool pad_one;
    Bool append_len;
} SHA256_Req #(numeric type bram_addr_sz_) deriving (Bits, FShow);

// TODO generalise?
typedef struct {
    Bit #(64) data_ptr;
    Bit #(64) data_len;
    Bit #(64) key_ptr;
    Bit #(64) key_len;
    Bit #(64) dest_ptr;
} HWCrypto_Regs deriving (Bits, Eq, FShow);


endpackage
