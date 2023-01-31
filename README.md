# Hardware SHA256 Hashing module
This is a Bluespec implementation of a custom SHA256 hashing module which uses
DMA for data access. CHERI support can be enabled by compiling using the
`HWCRYPTO_CHERI` macro and configured with `HWCRYPTO_CHERI_FAT` and
`HWCRYPTO_CHERI_INT_CHECK`.

## AXI Interfaces
The module exposes an AXI4 Subordinate (S) interface and an AXI4 (M) Manager
interface.
The S interface is used for accessing internal registers, and the M interface
is used to access for data access.

## Registers
This module has 6 registers which are exposed via the AXI S interface:
* Data Pointer register
  * This is the location of the first byte of data to be processed
* Key Pointer register
  * This is the location of the first byte of the key to be used
* Destination Pointer register
  * This is the location of the first byte of the result to be written
* Data Length register
  * This is the length in bytes of the data to be processed
* Key Length register
  * This is the length in bytes of the key to be used
* Status register
  * This is the status and control register
    Currently it has one field:
    * Status bit (Bit 0 / LSB)
      * When read, indicates whether the entire engine is active (1) or idle (0)
      * Writing a 1 to this field starts the engine's execution

The address offset of each register from the base address depends on whether
CHERI support is enabled. See the indexes in `src_HWCrypto/HWCrypto_Reg_Handler.bsv` for details.

## Usage
Typical usage:
* Write the Data, Key and Destination pointer registers with addresses in
  memory reachable by the M port where the data, key and result should be.
  Writes to the registers should be register-sized and single-flit except for
  writes to the pointer registers when CHERI is enabled, which should be two-flit
  and half-capability-sized.
* Write the Data and Key length register with the data and key lengths in bytes
* Trigger execution by writing a 1 to the LSB of the Status register
