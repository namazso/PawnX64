/**
* @file amx_posix.cpp
* @brief AMX abstract virtual machine, POSIX bits.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _BSD_SOURCE 1

#include "amx_internal.hpp"

#if defined(AMX_POSIX)

#include <atomic>
#include <cassert>
#include <mutex>

#include <signal.h>
#include <sys/mman.h>

#if defined(__has_include)
#if __has_include(<ucontext.h>)
#include <ucontext.h>
#endif
#if __has_include(<sys/ucontext.h>)
#include <sys/ucontext.h>
#endif
#endif

#if defined(MAP_ANON)
#define AMX_MAP_ANON MAP_ANON
#elif defined(MAP_ANONYMOUS)
#define AMX_MAP_ANON MAP_ANONYMOUS
#else
#error Anonymous mappings required
#endif

#ifdef MAP_NORESERVE
#define AMX_MAP_NORESERVE MAP_NORESERVE
#else
#define AMX_MAP_NORESERVE (0)
#endif

class spin_lock
{
  std::atomic_flag locked = ATOMIC_FLAG_INIT;

public:
  void lock()
  {
    while (locked.test_and_set(std::memory_order_acquire)) {}
  }
  void unlock()
  {
    locked.clear(std::memory_order_release);
  }
};

struct list_entry {
  list_entry* next;
  amx* instance;
};

list_entry* amx_instances{};
spin_lock amx_instances_lock{};

void amx_instance_register(struct amx* instance)
{
  const auto entry = new list_entry;
  entry->instance = instance;
  {
    std::lock_guard<spin_lock> guard(amx_instances_lock);
    entry->next = amx_instances;
    amx_instances = entry;
  }
}

void amx_instance_unregister(struct amx* instance)
{
  list_entry* to_remove = nullptr;
  {
    std::lock_guard<spin_lock> guard(amx_instances_lock);
    auto next_of_previous = &amx_instances;
    for (auto it = amx_instances; it; it = it->next)
    {
      if (it->instance == instance)
      {
        to_remove = it;
        *next_of_previous = to_remove->next;
        break;
      }
      next_of_previous = &it->next;
    }
  }
  assert(to_remove);
  delete to_remove;
}

amx* amx_find_instance_by_rip(void* rip)
{
  amx* instance = nullptr;
  {
    std::lock_guard<spin_lock> guard(amx_instances_lock);
    for (auto it = amx_instances; it; it = it->next)
    {
      const auto current = it->instance;
      if ((char*)rip >= (char*)current->cod && (char*)rip < (char*)current->cip_stub_base)
      {
        instance = current;
        break;
      }
    }
  }
  return instance;
}

extern "C" void amx_cell_read_throws();
extern "C" void amx_cell_read_except();

__asm__(R"(
.text
.balign 16
.globl amx_cell_read
amx_cell_read:
  # rdi = struct amx* amx
  # rsi = amx_cell va
  # rdx = amx_cell* out

  # truncate VA
  mov %esi, %esi

  # set success
  xor %eax, %eax

  # write 0 to read value
  movq %rax, (%rdx)

  # load DAT
  movq 16(%rdi), %rcx

.globl amx_cell_read_throws
amx_cell_read_throws:
  movq (%rcx, %rsi), %rcx
  movq %rcx, (%rdx)

.globl amx_cell_read_except
amx_cell_read_except:

  ret
  
.globl _amx_cell_read
.set _amx_cell_read, amx_cell_read
.globl _amx_cell_read_throws
.set _amx_cell_read_throws, amx_cell_read_throws
.globl _amx_cell_read_except
.set _amx_cell_read_except, amx_cell_read_except

)");

extern "C" void amx_cell_write_throws();
extern "C" void amx_cell_write_except();

__asm__(R"(
.text
.balign 16
.globl amx_cell_write
amx_cell_write:
  # rdi = struct amx* amx
  # rsi = amx_cell va
  # rdx = amx_cell val

  # truncate VA
  mov %esi, %esi

  # set success
  xor %eax, %eax

  # load DAT
  movq 16(%rdi), %rcx

.globl amx_cell_write_throws
amx_cell_write_throws:
  movq %rdx, (%rcx, %rsi)

.globl amx_cell_write_except
amx_cell_write_except:

  ret
  
.globl _amx_cell_write
.set _amx_cell_write, amx_cell_write
.globl _amx_cell_write_throws
.set _amx_cell_write_throws, amx_cell_write_throws
.globl _amx_cell_write_except
.set _amx_cell_write_except, amx_cell_write_except

)");

int32_t amx_stack_offset = 0x28;

extern "C" void amx_enter_except();

__asm__(R"(
.text
.balign 16
.globl amx_enter
amx_enter:
  # we do the traditional prologue so that debuggers work better
  push %rbp
  mov %rsp, %rbp

  # dont forget to match this distance in the signal handler
  push %rbx
  push %r14
  push %r15
  push $0

  # first parameter = amx*
  mov %rdi, %r15

  # second parameter = target to call
  mov %rsi, %rax

  # load registers
  movq 0(%r15), %rdx		# pri
  movq 8(%r15), %rcx		# alt
  movq 16(%r15), %rbx		# dat
  movl 24(%r15), %esi		# frm
  movl 28(%r15), %edi		# stk
  movl 32(%r15), %r14d	# hea

  # actually do the called thing
  callq *%rax

  xor %eax, %eax

.globl amx_enter_except
amx_enter_except:

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  add $8, %rsp
  pop %r15
  pop %r14
  pop %rbx
  pop %rbp

  ret

.globl _amx_enter
.set _amx_enter, amx_enter
.globl _amx_enter_except
.set _amx_enter_except, amx_enter_except

)");

__asm__(R"(
.text
.balign 16
.globl amx_native
amx_native:
  mov %rsp, %r9
  and $-16, %rsp
  sub $0x8, %rsp
  push %r9

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  # first parameter = amx*
  mov %r15, %rdi

  # second parameter = native index from rax
  mov %rax, %rsi

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

  pop %rsp
  ret
  
.globl _amx_native
.set _amx_native, amx_native

)");

__asm__(R"(
.text
.balign 16
.globl amx_debug
amx_debug:
  mov %rsp, %r9
  and $-16, %rsp
  sub $0x8, %rsp
  push %r9

  # save registers
  movq %rdx, 0(%r15)		# pri
  movq %rcx, 8(%r15)		# alt
  movq %rbx, 16(%r15)		# dat
  movl %esi, 24(%r15)		# frm
  movl %edi, 28(%r15)		# stk
  movl %r14d, 32(%r15)	# hea

  # first parameter = amx*
  mov %r15, %rdi

  # second parameter = cip from r8
  mov %r8, %rsi

  # call the debug callback
  callq *56(%r15)

  # load registers
  movq 0(%r15), %rdx		# pri
  movq 8(%r15), %rcx		# alt
  movq 16(%r15), %rbx		# dat
  movl 24(%r15), %esi		# frm
  movl 28(%r15), %edi		# stk
  movl 32(%r15), %r14d	# hea

  pop %rsp
  ret
  
.globl _amx_debug
.set _amx_debug, amx_debug

)");

void* amx_mem_reserve()
{
  constexpr int flags = MAP_PRIVATE | AMX_MAP_ANON | AMX_MAP_NORESERVE;
  const auto ret = mmap(
    nullptr,
    AMX_ADDRESS_SPACE_SIZE + AMX_PAGE_SIZE,
    PROT_NONE,
    flags,
    -1,
    0);
  return ret == MAP_FAILED ? nullptr : ret;
}

void amx_mem_release(void* p)
{
  munmap(p, AMX_ADDRESS_SPACE_SIZE + AMX_PAGE_SIZE);
}

amx_status amx_mem_alloc(amx* amx, amx_cell va, amx_cell size)
{
  if (va > AMX_MAX_ADDRESS || size > AMX_MAX_ADDRESS || va + size > AMX_MAX_ADDRESS || (va & AMX_PAGE_OFFSET_MASK) || (size & AMX_PAGE_OFFSET_MASK))
    return AMX_INVALID_ARGUMENT;
  const auto base = (char*)amx->dat + va;
  constexpr int flags = MAP_PRIVATE | MAP_FIXED | AMX_MAP_ANON;
  const auto ptr = mmap(
    base,
    size,
    PROT_READ | PROT_WRITE,
    flags,
    -1,
    0);
  return ptr == MAP_FAILED ? AMX_RUNTIME_ERROR : AMX_SUCCESS;
}

amx_status amx_mem_free(amx* amx, amx_cell va, amx_cell size)
{
  if (va > AMX_MAX_ADDRESS || size > AMX_MAX_ADDRESS || va + size > AMX_MAX_ADDRESS || (va & AMX_PAGE_OFFSET_MASK) || (size & AMX_PAGE_OFFSET_MASK))
    return AMX_INVALID_ARGUMENT;
  const auto base = (char*)amx->dat + va;
  constexpr int flags = MAP_PRIVATE | AMX_MAP_ANON | AMX_MAP_NORESERVE;
  const auto ptr = mmap(
    base,
    size,
    PROT_NONE,
    flags,
    -1,
    0);
  return ptr == MAP_FAILED ? AMX_RUNTIME_ERROR : AMX_SUCCESS;
}

// returns true if handled with allocation
bool amx_handle_sigsegv(amx* amx, void* addr)
{
  if (amx->av_behavior == AMX_AV_ALLOCATE)
  {
    const auto va = (char*)addr - (char*)amx->dat;
    if (va < AMX_ADDRESS_SPACE_SIZE)
      return AMX_SUCCESS == amx_mem_alloc(amx, va & AMX_PAGE_MASK, AMX_PAGE_SIZE);
  }
  return false;
}

int amx_handle_signal(int signo, siginfo_t* info, void* context)
{
#if defined(__linux__) || defined(__sun)
#define MCONTEXT_RIP uc_mcontext.gregs[REG_RIP]
#define MCONTEXT_RSP uc_mcontext.gregs[REG_RSP]
#define MCONTEXT_RBP uc_mcontext.gregs[REG_RBP]
#define MCONTEXT_RDI uc_mcontext.gregs[REG_RDI]
#define MCONTEXT_RAX uc_mcontext.gregs[REG_RAX]
#elif defined(__HAIKU__)
#define MCONTEXT_RIP uc_mcontext.rip
#define MCONTEXT_RSP uc_mcontext.rsp
#define MCONTEXT_RBP uc_mcontext.rbp
#define MCONTEXT_RDI uc_mcontext.rdi
#define MCONTEXT_RAX uc_mcontext.rax
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
#define MCONTEXT_RIP uc_mcontext.mc_rip
#define MCONTEXT_RSP uc_mcontext.mc_rsp
#define MCONTEXT_RBP uc_mcontext.mc_rbp
#define MCONTEXT_RDI uc_mcontext.mc_rdi
#define MCONTEXT_RAX uc_mcontext.mc_rax
#elif defined(__NetBSD__)
#define MCONTEXT_RIP uc_mcontext.__gregs[REG_RIP]
#define MCONTEXT_RSP uc_mcontext.__gregs[REG_RSP]
#define MCONTEXT_RBP uc_mcontext.__gregs[REG_RBP]
#define MCONTEXT_RDI uc_mcontext.__gregs[REG_RDI]
#define MCONTEXT_RAX uc_mcontext.__gregs[REG_RAX]
#elif defined(__OpenBSD__)
#define MCONTEXT_RIP sc_rip
#define MCONTEXT_RSP sc_rsp
#define MCONTEXT_RBP sc_rbp
#define MCONTEXT_RDI sc_rdi
#define MCONTEXT_RAX sc_rax
#elif defined(__APPLE__) && defined(__MACH__)
#define MCONTEXT_RIP uc_mcontext->__ss.__rip
#define MCONTEXT_RSP uc_mcontext->__ss.__rsp
#define MCONTEXT_RBP uc_mcontext->__ss.__rbp
#define MCONTEXT_RDI uc_mcontext->__ss.__rdi
#define MCONTEXT_RAX uc_mcontext->__ss.__rax
#else
#error unknown system
#endif

  const auto ctx = (ucontext_t*)context;
  void* rip = (void*)ctx->MCONTEXT_RIP;
  auto amx = amx_find_instance_by_rip(rip);
  if (amx)
  {
    if ((signo != SIGSEGV && signo != SIGBUS) || !amx_handle_sigsegv(amx, info->si_addr))
    {
      amx_status status;
      switch (signo)
      {
      case SIGSEGV:
      case SIGBUS:
        status = AMX_ACCESS_VIOLATION;
        break;
      case SIGFPE:
        status = AMX_DIVIDE_BY_ZERO;
        break;
      case SIGTRAP:
      default:// shouldn't happen
        status = AMX_NATIVE_ERROR;
        break;
      }
      ctx->MCONTEXT_RIP = (intptr_t)(void*)&amx_enter_except;
      ctx->MCONTEXT_RSP = ctx->MCONTEXT_RBP - 0x20;
      ctx->MCONTEXT_RAX = status;
    }
    return 1;
  }

  if (signo == SIGSEGV || signo == SIGBUS)
  {
    void* target = nullptr;
    if (rip == (void*)&amx_cell_read_throws)
      target = (void*)&amx_cell_read_except;
    if (rip == (void*)&amx_cell_write_throws)
      target = (void*)&amx_cell_write_except;
    if (target)
    {
      amx = (struct amx*)ctx->MCONTEXT_RDI;
      if (!amx_handle_sigsegv(amx, info->si_addr))
      {
        ctx->MCONTEXT_RIP = (intptr_t)target;
        ctx->MCONTEXT_RAX = AMX_ACCESS_VIOLATION;
      }
      return 1;
    }
  }

  return 0;
}

#endif
