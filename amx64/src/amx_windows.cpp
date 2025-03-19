/**
* @file amx_windows.cpp
* @brief AMX abstract virtual machine, Windows bits.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#if defined(_WIN32) || defined(WIN32)

#include "amx_internal.hpp"

#include <Windows.h>
#include <excpt.h>

int32_t amx_stack_offset = 0x58;

extern "C" void amx_enter_internal(amx* amx, void* function);
__asm__(R"(
.text
.balign 16
.globl amx_enter_internal
.def amx_enter_internal; .scl 2; .type 32; .endef
.seh_proc amx_enter_internal
amx_enter_internal:
  push %rbp
  .seh_pushreg %rbp
  mov %rsp, %rbp # we actually only use this for stack size protection
  push %rbx
  .seh_pushreg %rbx
  push %rsi
  .seh_pushreg %rsi
  push %rdi
  .seh_pushreg %rdi
  push %r14
  .seh_pushreg %r14
  push %r15
  .seh_pushreg %r15
  sub $0x28, %rsp
  .seh_stackalloc 0x28
  .seh_endprologue

  # first parameter = amx*
  mov %rcx, %r15

  # second parameter = target to call
  mov %rdx, %rax

  # load registers
  movq 0(%r15), %rdx		# pri
  movq 8(%r15), %rcx		# alt
  movq 16(%r15), %rbx		# dat
  movl 24(%r15), %esi		# frm
  movl 28(%r15), %edi		# stk
  movl 32(%r15), %r14d	# hea

  # actually do the called thing
  callq *%rax

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  add $0x28, %rsp

  pop %r15
  pop %r14
  pop %rdi
  pop %rsi
  pop %rbx
  pop %rbp

  ret

.seh_endproc
)");

__asm__(R"(
.text
.balign 16
.globl amx_native
.def amx_native; .scl 2; .type 32; .endef
.seh_proc amx_native
amx_native:
  push %rbp
  .seh_pushreg %rbp
  mov %rsp, %rbp
  .seh_setframe %rbp, 0
  .seh_endprologue

  and $-16, %rsp

  sub $0x20, %rsp

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  # first parameter = amx*
  mov %r15, %rcx

  # second parameter = native index from rax
  mov %rax, %rdx

  # call the native callback
  callq *48(%r15)

  test %rax, %rax
  jnz all_good

  int3 # native reported failure, just throw. unwinder will take us back

all_good:
  # load registers
  movq 0(%r15), %rdx		# pri
  movq 8(%r15), %rcx		# alt
  movq 16(%r15), %rbx		# dat
  movl 24(%r15), %esi		# frm
  movl 28(%r15), %edi		# stk
  movl 32(%r15), %r14d	# hea

  mov %rbp, %rsp
  pop %rbp
  ret

.seh_endproc
)");

__asm__(R"(
.text
.balign 16
.globl amx_debug
.def amx_debug; .scl 2; .type 32; .endef
.seh_proc amx_debug
amx_debug:
  push %rbp
  .seh_pushreg %rbp
  mov %rsp, %rbp
  .seh_setframe %rbp, 0
  .seh_endprologue

  and $-16, %rsp

  sub $0x20, %rsp

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  # first parameter = amx*
  mov %r15, %rcx

  # second parameter = cip from r8
  mov %r8, %rdx

  # call the debug callback
  callq *56(%r15)

  # load registers
  movq 0(%r15), %rdx		# pri
  movq 8(%r15), %rcx		# alt
  movq 16(%r15), %rbx		# dat
  movl 24(%r15), %esi		# frm
  movl 28(%r15), %edi		# stk
  movl 32(%r15), %r14d	# hea

  mov %rbp, %rsp
  pop %rbp
  ret

.seh_endproc
)");

int amx_exception_filter(amx* amx, PEXCEPTION_POINTERS exp, amx_status& status)
{
  const auto record = exp->ExceptionRecord;
  if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && (char*)record->ExceptionInformation[1] >= (char*)amx->dat && (char*)record->ExceptionInformation[1] < ((char*)amx->dat + AMX_ADDRESS_SPACE_SIZE) && amx->av_behavior == AMX_AV_ALLOCATE)
  {
    const auto addr = record->ExceptionInformation[1];
    const auto addr_aligned = addr & AMX_PAGE_MASK;
    const auto va = (char*)addr_aligned - (char*)amx->dat;
    if (AMX_SUCCESS == amx_mem_alloc(amx, va, AMX_PAGE_SIZE))
      return EXCEPTION_CONTINUE_EXECUTION;
  }
  switch (record->ExceptionCode)
  {
  case EXCEPTION_ACCESS_VIOLATION:
    status = AMX_ACCESS_VIOLATION;
    break;
  case EXCEPTION_INT_DIVIDE_BY_ZERO:
    status = AMX_DIVIDE_BY_ZERO;
    break;
  case EXCEPTION_BREAKPOINT:
    status = AMX_NATIVE_ERROR;
    break;
  default:
    status = AMX_RUNTIME_ERROR;
    break;
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

amx_status amx_enter(amx* amx, void* function)
{
  amx_status status = AMX_SUCCESS;
  __try
  {
    amx_enter_internal(amx, function);
  }
  __except (amx_exception_filter(amx, GetExceptionInformation(), status))
  {
  }
  return status;
}

__declspec(noinline) void amx_cell_read_internal(amx* amx, amx_cell va, amx_cell* out)
{
  *out = *(amx_cell*)((char*)amx->dat + va);
}

__declspec(noinline) void amx_cell_write_internal(amx* amx, amx_cell va, amx_cell val)
{
  *(amx_cell*)((char*)amx->dat + va) = val;
}

amx_status amx_cell_read(amx* amx, amx_cell va, amx_cell* out)
{
  *out = 0;
  if (va > AMX_MAX_ADDRESS || (va & AMX_MISALIGN_MASK))
    return AMX_INVALID_ARGUMENT;
  amx_status status = AMX_SUCCESS;
  __try
  {
    amx_cell_read_internal(amx, (uint32_t)va, out);
  }
  __except (amx_exception_filter(amx, GetExceptionInformation(), status))
  {
  }
  return status;
}

amx_status amx_cell_write(amx* amx, amx_cell va, amx_cell val)
{
  if (va > AMX_MAX_ADDRESS || (va & AMX_MISALIGN_MASK))
    return AMX_INVALID_ARGUMENT;
  amx_status status = AMX_SUCCESS;
  __try
  {
    amx_cell_write_internal(amx, (uint32_t)va, val);
  }
  __except (amx_exception_filter(amx, GetExceptionInformation(), status))
  {
  }
  return status;
}

amx_status amx_mem_alloc(amx* amx, amx_cell va, amx_cell size)
{
  if (va > AMX_MAX_ADDRESS || size > AMX_MAX_ADDRESS || va + size > AMX_MAX_ADDRESS || (va & AMX_PAGE_OFFSET_MASK) || (size & AMX_PAGE_OFFSET_MASK))
    return AMX_INVALID_ARGUMENT;
  const auto base = (char*)amx->dat + va;
  const auto ptr = VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE);
  return ptr == nullptr ? AMX_RUNTIME_ERROR : AMX_SUCCESS;
}

amx_status amx_mem_free(amx* amx, amx_cell va, amx_cell size)
{
  if (va > AMX_MAX_ADDRESS || size > AMX_MAX_ADDRESS || va + size > AMX_MAX_ADDRESS || (va & AMX_PAGE_OFFSET_MASK) || (size & AMX_PAGE_OFFSET_MASK))
    return AMX_INVALID_ARGUMENT;
  const auto base = (char*)amx->dat + va;
  const auto result = VirtualFree(base, size, MEM_DECOMMIT);
  return result == FALSE ? AMX_RUNTIME_ERROR : AMX_SUCCESS;
}

void* amx_mem_reserve()
{
  return VirtualAlloc(nullptr, AMX_ADDRESS_SPACE_SIZE + AMX_PAGE_SIZE, MEM_RESERVE, PAGE_READWRITE);
}

void amx_mem_release(void* p)
{
  if (p)
    VirtualFree(p, 0, MEM_RELEASE);
}

void amx_instance_register(struct amx*)
{
}

void amx_instance_unregister(struct amx*)
{
}

BOOL APIENTRY DllMain(
  HMODULE mod,
  DWORD reason,
  LPVOID reserved)
{
  switch (reason)
  {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

extern "C" AMX_EXPORT int amx_handle_signal(int signo, void* info, void* context)
{
  return 1;
  // empty function for FFI users
}

#endif
