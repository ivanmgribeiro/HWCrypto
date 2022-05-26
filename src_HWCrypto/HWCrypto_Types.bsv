/*-
 * Copyright (c) 2022 Ivan Ribeiro
 * All rights reserved.
 *
 * This hardware was developed by University of Cambridge Computer Laboratory
 * (Department of Computer Science and Technology) under EPSRC award
 * EP/S030867/1 ("SIPP"); and by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

package HWCrypto_Types;

import CHERICap :: *;
import CHERICC_Fat :: *;

typedef Bit #(0) Token;
typedef enum {
`ifdef HWCRYPTO_CHERI
`ifndef HWCRYPTO_CHERI_INT_CHECK
    CHERI_ERROR,
`endif
`endif
    BUS_ERROR,
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

`ifdef HWCRYPTO_CHERI
`ifdef HWCRYPTO_CHERI_FAT
typedef CapReg HWCrypto_Ptr;
typedef Bit #(64) HWCrypto_Len;
`else
typedef CapMem HWCrypto_Ptr;
typedef Bit #(64) HWCrypto_Len;
`endif
`else
typedef Bit #(64) HWCrypto_Ptr;
typedef Bit #(64) HWCrypto_Len;
`endif

typedef struct {
    HWCrypto_Ptr data_ptr;
    HWCrypto_Ptr key_ptr;
    HWCrypto_Ptr dest_ptr;
    HWCrypto_Len data_len;
    HWCrypto_Len key_len;
} HWCrypto_Regs deriving (Bits, Eq, FShow);


endpackage
