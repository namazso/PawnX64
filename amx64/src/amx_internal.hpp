/**
* @file amx_internal.hpp
* @brief Internal header for AMX abstract virtual machine.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#pragma once
#define AMX_EXPOSE_DANGEROUS_FEATURES
#include <asmjit/asmjit.h>
#include <cstddef>

#include "amx.h"
#include "amx_loader.h"

#define AMX_ADDRESS_SPACE_SIZE (amx_cell)(0x100000000)
#define AMX_MAX_ADDRESS (AMX_ADDRESS_SPACE_SIZE - 1)
#define AMX_PAGE_OFFSET_MASK (amx_cell)(AMX_PAGE_SIZE - 1)
#define AMX_PAGE_MASK (~AMX_PAGE_OFFSET_MASK)
#define AMX_MISALIGN_MASK (amx_cell)(sizeof(amx_cell) - 1)
#define AMX_ALIGN_MASK (~AMX_MISALIGN_MASK)

extern "C" amx_status amx_enter(amx* amx, void* function);

// not actually the prototype, do not call this from C
extern "C" void amx_native();

// not actually the prototype, do not call this from C
extern "C" void amx_debug();

void* amx_mem_reserve();

void amx_mem_release(void* p);

void amx_empty_debug_callback(struct amx*, amx_cell cip);

void amx_instance_register(struct amx*);

void amx_instance_unregister(struct amx*);

extern int32_t amx_stack_offset;

// this is separated into another struct so that "offsetof" is legal
struct amx_core {
  // primary register (ALU, general purpose).
  uint64_t pri{};

  // alternate register (general purpose).
  uint64_t alt{};

  // pointer to the 4 GB reserved memory assigned to this VM
  void* dat{};

  // stack frame pointer; stack-relative memory reads & writes are relative to the address in this register.
  uint32_t frm{};

  // stack index, indicates the current position in the stack. The stack runs downwards from the STP register towards zero.
  uint32_t stk{};

  // heap pointer. Dynamically allocated memory comes from the heap and the HEA register indicates the top of the heap.
  uint32_t hea{};

  // behavior on encountering access violation.
  amx_access_violation_behavior av_behavior{AMX_AV_TERMINATE};

  // base of code allocation
  void* cod{};

  // C callback to call on SYSREQ
  amx_native_callback native_callback{};

  // C callback to call before every instruction
  amx_debug_callback debug_callback = &amx_empty_debug_callback;

  // generated code calls this on a SYSREQ
  void (*native_target)() = &amx_native;

  // generated code calls this before every instruction
  void (*debug_target)() = &amx_debug;

  // arbitrary user data
  void* userdata{};

  // max real world stack size
  uint32_t max_stack_size = 0x4000; // 16k, matching the default AMX stack size
};

struct amx : amx_core {
  asmjit::JitRuntime runtime;

  void* cip_stub_base{};

  uint64_t cip_count{};

  amx();
  ~amx();
};

static_assert(offsetof(amx_core, pri) == 0, "");
static_assert(offsetof(amx_core, alt) == 8, "");
static_assert(offsetof(amx_core, dat) == 16, "");
static_assert(offsetof(amx_core, frm) == 24, "");
static_assert(offsetof(amx_core, stk) == 28, "");
static_assert(offsetof(amx_core, hea) == 32, "");
static_assert(offsetof(amx_core, native_callback) == 48, "");
static_assert(offsetof(amx_core, debug_callback) == 56, "");
