# PawnX64

## About

A simple JIT compiler library for Pawn p-code for amd64.

## Supported platforms

Generally any AMD64 Windows or POSIX with a C++11 compiler should be enough. Additionally, the code was tested on:

- Windows
- Linux (tested on RHEL 7)
- FreeBSD

## Changes from original Pawn

### Different API

The PawnX64 API tries to encourage safe and isolated usage. The provided interfaces are mostly only FFI-friendly primitives that allow you to implement higher level constructs yourself.  

### Different memory layout

Unlike the original Pawn which implements a Neumann architecture, PawnX64 implements a Harvard architecture. This means code and data are in different memory banks, and code cannot be read or written. The `DAT` register has a constant value of `0`.

Memory isolation of Pawn data is achieved by truncating data access to 32 bits and adding a constant base, where 4 GB of memory is reserved. This provides very high performance and easy to enforce sandboxing.

Additionally, the stack (=`STP`) starts at *2 GB - 32* to have extra space to grow in cases where a native is calling back Pawn code.

The region between *2 GB* and *4 GB* is never used by the runtime. It can be used for allocating and passing arrays to Pawn functions.

### Modified instruction set

The following instructions are not implemented:

- `LCTRL STP`

`STP` is not stored by the implementation, and therefore cannot be retrieved.

The following instructions are modified:

- `RET`
- `RETN`
- `CALL`

The return address on the Pawn stack is set but not used, instead control flow is tracked on a shadow stack inaccessible to Pawn.

### No amx file provided library loading

Each loaded amx module can only use the natives that were registered to the loader. Modules can no longer instruct to load arbitrary shared libraries.

### No standard libraries

Due to changes in ABI, the Pawn standard libraries are unavailable.

## License

[Mozilla Public License Version 2.0](LICENSE)
