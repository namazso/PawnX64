/**
* @file amx_compile.cpp
* @brief AMX abstract virtual machine, machine code compiler.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "amx_internal.hpp"
#include <algorithm>
#include <asmjit/asmjit.h>
#include <cassert>
#include <vector>

constexpr static bool OPCODE_HAS_OPERAND[] = {
  false, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true,
  false, true, true, true, true, false, false, false, false, false, false, true, true, true, false, false,
  false, true, true, true, true, false, false, false, true, true, false, false, false, false, false, false,
  false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
  true, true, true, true, true, true, true, false, false, false, false};

enum : amx_cell
{
  OP_NOP = 0,
  OP_LOAD_PRI,
  OP_LOAD_ALT,
  OP_LOAD_S_PRI,
  OP_LOAD_S_ALT,
  OP_LREF_S_PRI,
  OP_LREF_S_ALT,
  OP_LOAD_I,
  OP_LODB_I,
  OP_CONST_PRI,
  OP_CONST_ALT,
  OP_ADDR_PRI,
  OP_ADDR_ALT,
  OP_STOR,
  OP_STOR_S,
  OP_SREF_S,
  OP_STOR_I,
  OP_STRB_I,
  OP_ALIGN_PRI,
  OP_LCTRL,
  OP_SCTRL,
  OP_XCHG,
  OP_PUSH_PRI,
  OP_PUSH_ALT,
  OP_PUSHR_PRI,
  OP_POP_PRI,
  OP_POP_ALT,
  OP_PICK,
  OP_STACK,
  OP_HEAP,
  OP_PROC,
  OP_RET,
  OP_RETN,
  OP_CALL,
  OP_JUMP,
  OP_JZER,
  OP_JNZ,
  OP_SHL,
  OP_SHR,
  OP_SSHR,
  OP_SHL_C_PRI,
  OP_SHL_C_ALT,
  OP_SMUL,
  OP_SDIV,
  OP_ADD,
  OP_SUB,
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_NOT,
  OP_NEG,
  OP_INVERT,
  OP_EQ,
  OP_NEQ,
  OP_SLESS,
  OP_SLEQ,
  OP_SGRTR,
  OP_SGEQ,
  OP_INC_PRI,
  OP_INC_ALT,
  OP_INC_I,
  OP_DEC_PRI,
  OP_DEC_ALT,
  OP_DEC_I,
  OP_MOVS,
  OP_CMPS,
  OP_FILL,
  OP_HALT,
  OP_BOUNDS,
  OP_SYSREQ,
  OP_SWITCH,
  OP_SWAP_PRI,
  OP_SWAP_ALT,
  OP_BREAK,
  OP_CASETBL,
  /* ----- */
  OP_NUM_OPCODES
};

bool is_packable32(uint64_t v)
{
  return (int64_t)v == (int64_t)(int32_t)v;
}

bool is_natural32(uint64_t v)
{
  return v < 0x80000000;
}

enum amx_status amx_code_load(
  struct amx* amx,
  const amx_cell* code,
  amx_cell count,
  uint64_t codegen_control,
  amx_native_index_translator translator,
  void* userparam)
{
  using namespace asmjit;
  using namespace asmjit::x86;

  amx_code_free(amx);

  CodeHolder holder;
  holder.init(amx->runtime.environment());
  x86::Assembler a(&holder);

  std::vector<Label> labels(count);
  std::generate(begin(labels), end(labels), [&a]() {
    return a.newLabel();
  });

  std::vector<size_t> control_flow_targets;

  // scratch  - rax
  // scratch2 - r9
  // amx*     - r15 - must be nonvolatile on Win64 and SysV
  // old rsp  - rbp - needed for Linux unwinding, not used on Windows
  // PRI - rdx
  // ALT - rcx
  // DAT - rbx
  // FRM - esi
  // STK - edi
  // HEA - r14d
  // CIP - r8d if debug level 1
  // COD - unused
  // STP - unused

  const auto& PRI = rdx;
  const auto& ALT = rcx;
  const auto& DAT = rbx;
  const auto& FRM = esi;
  const auto& STK = edi;
  const auto& HEA = r14d;
  const auto& CIP = r8d;
  const auto& AMX = r15;
  const auto& scratch = rax;
  const auto& scratch2 = r9;

  constexpr static auto native_target_offset = offsetof(amx_core, native_target);
  constexpr static auto debug_target_offset = offsetof(amx_core, debug_target);
  constexpr static auto max_stack_size_offset = offsetof(amx_core, max_stack_size);

  const auto cip_stubs = a.newLabel();

  for (size_t i = 0; i < count;)
  {
    const auto old_i = i;
    const auto opcode = code[i++];
    if (opcode >= OP_NUM_OPCODES)
      return AMX_MALFORMED_CODE;
    amx_cell operand = 0;
    if (OPCODE_HAS_OPERAND[opcode])
    {
      if (i + 1 > count)
        return AMX_MALFORMED_CODE;
      operand = code[i++];
    }

#ifdef NDEBUG
#define V(...)                                               \
  do {                                                       \
    if (kErrorOk != (__VA_ARGS__)) return AMX_COMPILE_ERROR; \
  } while (0)
#else
#define V(...)                                    \
  do {                                            \
    if (kErrorOk != (__VA_ARGS__)) assert(false); \
  } while (0)
#endif

    V(a.bind(labels[old_i]));

    if (codegen_control & AMX_CODEGEN_CONTROL_DEBUG1)
      V(a.mov(CIP, imm((uint32_t)(old_i * sizeof(amx_cell)))));
    if (codegen_control & AMX_CODEGEN_CONTROL_DEBUG2)
      V(a.call(qword_ptr(AMX, debug_target_offset)));

#define PUSH(arg)                                  \
  do {                                             \
    V(a.sub(STK, imm((int32_t)sizeof(amx_cell)))); \
    V(a.mov(qword_ptr(DAT, STK.r64()), (arg)));    \
  } while (0)

#define POP(arg)                                   \
  do {                                             \
    V(a.mov((arg), qword_ptr(DAT, STK.r64())));    \
    V(a.add(STK, imm((int32_t)sizeof(amx_cell)))); \
  } while (0)

    switch (opcode)
    {
    case OP_BREAK:
    case OP_NOP:
      V(a.nop());
      break;

    case OP_LOAD_PRI:
      if (!is_natural32(operand))
        return AMX_UNSUPPORTED;
      V(a.mov(PRI, qword_ptr(DAT, (int32_t)operand)));
      break;
    case OP_LOAD_ALT:
      if (!is_natural32(operand))
        return AMX_UNSUPPORTED;
      V(a.mov(ALT, qword_ptr(DAT, (int32_t)operand)));
      break;

    case OP_LOAD_S_PRI:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(PRI, qword_ptr(DAT, scratch)));
      break;
    case OP_LOAD_S_ALT:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(ALT, qword_ptr(DAT, scratch)));
      break;

    case OP_LREF_S_PRI:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(scratch, qword_ptr(DAT, scratch)));
      V(a.mov(PRI, qword_ptr(DAT, scratch)));
      break;
    case OP_LREF_S_ALT:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(scratch, qword_ptr(DAT, scratch)));
      V(a.mov(ALT, qword_ptr(DAT, scratch)));
      break;

    case OP_LOAD_I:
      V(a.mov(scratch.r32(), PRI.r32()));
      V(a.mov(PRI, qword_ptr(DAT, scratch)));
      break;

    case OP_LODB_I:
      V(a.mov(scratch.r32(), PRI.r32()));
      switch (operand)
      {
      case 1:
        V(a.xor_(PRI, PRI));
        V(a.mov(PRI.r8(), byte_ptr(DAT, scratch)));
        break;
      case 2:
        V(a.xor_(PRI, PRI));
        V(a.mov(PRI.r16(), word_ptr(DAT, scratch)));
        break;
      case 4:
        V(a.mov(PRI.r32(), dword_ptr(DAT, scratch)));
        break;
      default:
        return AMX_MALFORMED_CODE;
      }
      break;

    case OP_CONST_PRI:
      V(a.mov(PRI, imm(operand)));
      break;
    case OP_CONST_ALT:
      V(a.mov(ALT, imm(operand)));
      break;

    case OP_ADDR_PRI:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(PRI, qword_ptr(FRM.r64(), (int32_t)operand)));
      break;
    case OP_ADDR_ALT:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(ALT, qword_ptr(FRM.r64(), (int32_t)operand)));
      break;

    case OP_STOR:
      if (!is_natural32(operand))
        return AMX_UNSUPPORTED;
      V(a.mov(qword_ptr(DAT, (int32_t)operand), PRI));
      break;

    case OP_STOR_S:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(qword_ptr(DAT, scratch), PRI));
      break;

    case OP_SREF_S:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(FRM, (int32_t)operand)));
      V(a.mov(scratch.r32(), dword_ptr(DAT, scratch)));
      V(a.mov(qword_ptr(DAT, scratch), PRI));
      break;

    case OP_STOR_I:
      V(a.mov(scratch.r32(), ALT.r32()));
      V(a.mov(qword_ptr(DAT, scratch), PRI));
      break;

    case OP_STRB_I:
      V(a.mov(scratch.r32(), ALT.r32()));
      switch (operand)
      {
      case 1:
        V(a.mov(byte_ptr(DAT, scratch), PRI.r8()));
        break;
      case 2:
        V(a.mov(word_ptr(DAT, scratch), PRI.r16()));
        break;
      case 4:
        V(a.mov(dword_ptr(DAT, scratch), PRI.r32()));
        break;
      default:
        return AMX_MALFORMED_CODE;
      }
      break;

    case OP_ALIGN_PRI:
      if (operand < sizeof(amx_cell))
        V(a.xor_(PRI, imm((int8_t)(sizeof(amx_cell) - operand))));
      break;

    case OP_LCTRL:
      switch (operand)
      {
      case 0:
        V(a.xor_(PRI, PRI));// COD, always 0 for us
        break;
      case 1:
        V(a.xor_(PRI, PRI));// DAT, always 0 for us
        break;
      case 2:
        V(a.mov(PRI.r32(), HEA));
        break;
      case 3:
        return AMX_UNSUPPORTED;// STP, we could technically support it if we stored it
      case 4:
        V(a.mov(PRI.r32(), STK));
        break;
      case 5:
        V(a.mov(PRI.r32(), FRM));
        break;
      case 6:
        V(a.mov(PRI, i * sizeof(amx_cell)));// CIP
        break;
      default:
        return AMX_MALFORMED_CODE;
      }
      break;

    case OP_SCTRL:
      switch (operand)
      {
      case 2:
        V(a.mov(HEA, PRI.r32()));
        break;
      case 4:
        V(a.mov(STK, PRI.r32()));
        break;
      case 5:
        V(a.mov(FRM, PRI.r32()));
        break;
      case 6: {
        const auto check_success = a.newLabel();
        V(a.and_(PRI.r32(), imm(-8)));
        V(a.cmp(PRI.r32(), imm(count * sizeof(amx_cell))));
        V(a.jl(check_success));
        V(a.int3());
        V(a.bind(check_success));
        V(a.lea(scratch, qword_ptr(cip_stubs, PRI)));
        V(a.jmp(scratch));
      }
      break;
      default:
        return AMX_MALFORMED_CODE;
      }
      break;

    case OP_XCHG:
      V(a.mov(scratch, ALT));
      V(a.mov(ALT, PRI));
      V(a.mov(PRI, scratch));
      break;

    case OP_PUSH_PRI:
      PUSH(PRI);
      break;
    case OP_PUSH_ALT:
      PUSH(ALT);
      break;

    case OP_PUSHR_PRI:
      PUSH(PRI);// PRI + DAT, but DAT is 0
      break;

    case OP_POP_PRI:
      POP(PRI);
      break;
    case OP_POP_ALT:
      POP(ALT);
      break;

    case OP_PICK:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.lea(scratch.r32(), dword_ptr(STK, (int32_t)operand)));
      V(a.mov(PRI, qword_ptr(DAT, scratch)));
      break;

    case OP_STACK:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.add(STK, imm((int32_t)operand)));
      V(a.mov(ALT, STK.r64()));
      break;

    case OP_HEAP:
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;
      V(a.mov(ALT, HEA.r64()));
      V(a.add(HEA, imm((int32_t)operand)));
      break;

    case OP_PROC:
      PUSH(FRM);
      V(a.mov(FRM, STK));
      break;

    case OP_RET:
      POP(FRM);
      V(a.add(STK, imm((int32_t)sizeof(amx_cell))));// discard CIP
      V(a.ret());                                   // do a real return
      break;

    case OP_RETN:
      POP(FRM);
      V(a.add(STK, imm((int32_t)sizeof(amx_cell))));// discard CIP
      V(a.mov(scratch, qword_ptr(DAT, STK)));
      V(a.lea(STK, dword_ptr(STK, scratch.r32(), 0, sizeof(amx_cell))));
      V(a.ret());// do a real return
      break;

    case OP_CALL: {
      PUSH(imm((int32_t)(i * sizeof(amx_cell))));
      const auto target_idx = ((old_i * sizeof(amx_cell)) + operand) / sizeof(amx_cell);
      if (target_idx >= count)
        return AMX_MALFORMED_CODE;
      if (codegen_control & AMX_CODEGEN_CONTROL_CALL_DEPTH)
      {
        V(a.mov(scratch.r32(), dword_ptr(AMX, max_stack_size_offset)));
        V(a.lea(scratch, qword_ptr(rsp, scratch, 0, amx_stack_offset)));
        V(a.cmp(rbp, scratch));
        const auto ok = a.newLabel();
        V(a.jle(ok));
        V(a.int3());
        V(a.bind(ok));
      }
      // we need these stupid thunks to confuse Windows unwinder enough to pass through the exception
      // as a bonus it even aligns the stack too
      const auto thunk = a.newLabel();
      const auto after_thunk = a.newLabel();
      V(a.call(thunk));
      V(a.jmp(after_thunk));
      V(a.bind(thunk));
      V(a.call(labels[target_idx]));
      V(a.ret());
      V(a.bind(after_thunk));
      control_flow_targets.push_back(target_idx);
    }
    break;

    case OP_JUMP: {
      const auto target_idx = ((old_i * sizeof(amx_cell)) + operand) / sizeof(amx_cell);
      if (target_idx >= count)
        return AMX_MALFORMED_CODE;
      V(a.jmp(labels[target_idx]));
      control_flow_targets.push_back(target_idx);
    }
    break;

    case OP_JZER: {
      V(a.test(PRI, PRI));
      const auto not_taken = a.newLabel();
      V(a.jnz(not_taken));
      const auto target_idx = ((old_i * sizeof(amx_cell)) + operand) / sizeof(amx_cell);
      if (target_idx >= count)
        return AMX_MALFORMED_CODE;
      V(a.jmp(labels[target_idx]));
      control_flow_targets.push_back(target_idx);
      V(a.bind(not_taken));
    }
    break;

    case OP_JNZ: {
      V(a.test(PRI, PRI));
      const auto not_taken = a.newLabel();
      V(a.jz(not_taken));
      const auto target_idx = ((old_i * sizeof(amx_cell)) + operand) / sizeof(amx_cell);
      if (target_idx >= count)
        return AMX_MALFORMED_CODE;
      V(a.jmp(labels[target_idx]));
      control_flow_targets.push_back(target_idx);
      V(a.bind(not_taken));
    }
    break;

    case OP_SHL:
      V(a.shl(PRI, ALT.r8()));
      break;

    case OP_SHR:
      V(a.shr(PRI, ALT.r8()));
      break;

    case OP_SSHR:
      V(a.sar(PRI, ALT.r8()));
      break;

    case OP_SHL_C_PRI:
      V(a.shl(PRI, imm((uint8_t)operand)));
      break;

    case OP_SHL_C_ALT:
      V(a.shl(ALT, imm((uint8_t)operand)));
      break;

    case OP_SMUL:
      V(a.imul(PRI, ALT));
      break;

    case OP_SDIV: {
      // obviously the simplest way to do division
      // generated via https://godbolt.org/z/qvvhqrzjz

      const auto label5 = a.newLabel();
      const auto label1 = a.newLabel();
      const auto label4 = a.newLabel();
      const auto label6 = a.newLabel();
      const auto label_end = a.newLabel();
      V(a.mov(scratch2, PRI));
      V(a.mov(scratch, ALT));
      V(a.or_(scratch, PRI));
      V(a.shr(scratch, imm(32)));
      V(a.je(label1));
      V(a.mov(scratch, ALT));
      V(a.cqo(PRI, scratch));
      V(a.idiv(scratch2));
      V(a.mov(ALT, PRI));
      V(a.mov(PRI, scratch));
      V(a.test(ALT, ALT));
      V(a.je(label4));
      V(a.bind(label5));
      V(a.mov(scratch, ALT));
      V(a.xor_(scratch, scratch2));
      V(a.js(label6));
      V(a.jmp(label_end));
      V(a.bind(label1));
      V(a.mov(scratch.r32(), ALT.r32()));
      V(a.xor_(PRI.r32(), PRI.r32()));
      V(a.div(scratch2.r32()));
      V(a.mov(ALT.r32(), PRI.r32()));
      V(a.mov(PRI.r32(), scratch.r32()));
      V(a.test(ALT, ALT));
      V(a.jne(label5));
      V(a.bind(label4));
      V(a.xor_(ALT.r32(), ALT.r32()));
      V(a.jmp(label_end));
      V(a.bind(label6));
      V(a.dec(PRI));
      V(a.add(ALT, scratch2));
      V(a.bind(label_end));
    }
    break;

    case OP_ADD:
      V(a.add(PRI, ALT));
      break;

    case OP_SUB:
      V(a.neg(PRI));
      V(a.add(PRI, ALT));
      break;

    case OP_AND:
      V(a.and_(PRI, ALT));
      break;

    case OP_OR:
      V(a.or_(PRI, ALT));
      break;

    case OP_XOR:
      V(a.xor_(PRI, ALT));
      break;

    case OP_NOT:
      V(a.test(PRI, PRI));
      V(a.setz(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_NEG:
      V(a.neg(PRI));
      break;

    case OP_INVERT:
      V(a.not_(PRI));
      break;

    case OP_EQ:
      V(a.cmp(PRI, ALT));
      V(a.sete(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_NEQ:
      V(a.cmp(PRI, ALT));
      V(a.setne(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_SLESS:
      V(a.cmp(PRI, ALT));
      V(a.setl(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_SLEQ:
      V(a.cmp(PRI, ALT));
      V(a.setle(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_SGRTR:
      V(a.cmp(PRI, ALT));
      V(a.setg(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_SGEQ:
      V(a.cmp(PRI, ALT));
      V(a.setge(scratch.r8()));
      V(a.movzx(PRI.r32(), scratch.r8()));
      break;

    case OP_INC_PRI:
      V(a.inc(PRI));
      break;
    case OP_INC_ALT:
      V(a.inc(ALT));
      break;

    case OP_INC_I:
      V(a.mov(scratch.r32(), PRI.r32()));
      V(a.inc(qword_ptr(DAT, scratch)));
      break;

    case OP_DEC_PRI:
      V(a.dec(PRI));
      break;
    case OP_DEC_ALT:
      V(a.dec(ALT));
      break;

    case OP_DEC_I:
      V(a.mov(scratch.r32(), PRI.r32()));
      V(a.dec(qword_ptr(DAT, scratch)));
      break;

    case OP_MOVS:
      if ((operand & 7) != 0 || !is_natural32(operand))
        return AMX_UNSUPPORTED;

      // we always unroll. yes this could be way more performant with a better memcpy,
      // but this instruction is pretty rare either way.
      for (size_t j = 0; j < operand; j += sizeof(amx_cell))
      {
        V(a.lea(scratch.r32(), dword_ptr(PRI.r32(), (int32_t)j)));
        V(a.mov(scratch2, qword_ptr(DAT, scratch)));
        V(a.lea(scratch.r32(), dword_ptr(ALT.r32(), (int32_t)j)));
        V(a.mov(qword_ptr(DAT, scratch), scratch2));
      }
      break;

    case OP_CMPS: {
      if ((operand & 7) != 0 || !is_natural32(operand))
        return AMX_UNSUPPORTED;

      const auto end_label = a.newLabel();

      V(a.mov(scratch2, PRI));
      V(a.xor_(PRI, PRI));

      // we always unroll. yes this could be way more performant with a better memcmp,
      // but this instruction is pretty rare either way.
      for (size_t j = 0; j < operand; j += sizeof(amx_cell))
      {
        V(a.lea(scratch.r32(), dword_ptr(ALT.r32(), (int32_t)j)));
        V(a.mov(PRI, qword_ptr(DAT, scratch)));
        V(a.lea(scratch.r32(), dword_ptr(scratch2.r32(), (int32_t)j)));
        V(a.sub(PRI, qword_ptr(DAT, scratch)));
        V(a.jnz(end_label));
      }
      V(a.bind(end_label));
    }
    break;

    case OP_FILL:
      if ((operand & 7) != 0 || !is_natural32(operand))
        return AMX_UNSUPPORTED;

      // we always unroll. yes this could be way more performant with a better memset,
      // but this instruction is pretty rare either way.
      for (size_t j = 0; j < operand; j += sizeof(amx_cell))
      {
        V(a.lea(scratch.r32(), dword_ptr(ALT.r32(), (int32_t)j)));
        V(a.mov(qword_ptr(DAT, scratch), PRI));
      }
      break;

    case OP_HALT:
      V(a.mov(PRI, imm(operand)));
      V(a.ret());
      break;

    case OP_BOUNDS: {
      if (!is_packable32(operand))
        return AMX_UNSUPPORTED;

      const auto ok = a.newLabel();

      V(a.cmp(PRI, imm((int32_t)operand)));
      V(a.jle(ok));
      V(a.int3());
      V(a.bind(ok));
    }
    break;

    case OP_SYSREQ:
      V(a.mov(scratch, imm(translator(userparam, amx, operand))));
      V(a.call(qword_ptr(AMX, native_target_offset)));
      break;

    case OP_SWITCH: {
      const auto cell_bytes = sizeof(amx_cell);
      const auto max_address = count * cell_bytes;

      if (operand & 7)
        return AMX_MALFORMED_CODE;

      auto casetbl = (old_i * cell_bytes) + operand;
      if (casetbl >= max_address || (casetbl + 2 * cell_bytes) >= max_address)
        return AMX_MALFORMED_CODE;

      const auto casetbl_opcode = code[casetbl / cell_bytes];
      casetbl += cell_bytes;
      if (casetbl_opcode != OP_CASETBL)
        return AMX_MALFORMED_CODE;

      auto record_count = code[casetbl / cell_bytes];
      casetbl += cell_bytes;

      const auto default_case_offset = code[casetbl / cell_bytes];
      casetbl += cell_bytes;

      const auto default_case = casetbl - cell_bytes * 2 + default_case_offset;
      if (default_case >= max_address)
        return AMX_MALFORMED_CODE;

      const auto default_case_idx = default_case / cell_bytes;
      const auto& default_case_label = labels[default_case_idx];
      control_flow_targets.emplace_back(default_case_idx);

      if (casetbl + record_count * 2 > max_address)
        return AMX_MALFORMED_CODE;

      while (record_count)
      {
        const auto test = code[casetbl / cell_bytes];
        casetbl += cell_bytes;

        const auto jmp_offset = code[casetbl / cell_bytes];
        casetbl += cell_bytes;

        const auto jmp_target = casetbl - cell_bytes * 2 + jmp_offset;
        if (jmp_target >= max_address)
          return AMX_MALFORMED_CODE;

        const auto jmp_target_idx = jmp_target / cell_bytes;
        const auto& jmp_label = labels[jmp_target_idx];
        control_flow_targets.emplace_back(jmp_target_idx);

        if (is_packable32(test))
        {
          V(a.cmp(PRI, imm((int32_t)test)));
        }
        else
        {
          V(a.mov(scratch, imm(test)));
          V(a.cmp(PRI, scratch));
        }

        V(a.je(jmp_label));

        --record_count;
      }

      V(a.jmp(default_case_label));
    }
    break;

    case OP_SWAP_PRI:
      V(a.mov(scratch, qword_ptr(DAT, STK)));
      V(a.mov(qword_ptr(DAT, STK), PRI));
      V(a.mov(PRI, scratch));
      break;
    case OP_SWAP_ALT:
      V(a.mov(scratch, qword_ptr(DAT, STK)));
      V(a.mov(qword_ptr(DAT, STK), ALT));
      V(a.mov(ALT, scratch));
      break;

    case OP_CASETBL: {
      if ((old_i + 2) >= count)
        return AMX_MALFORMED_CODE;
      const auto record_count = code[old_i + 1];
      i += 2 + record_count * 2;
    }
    break;

    default:
      return AMX_UNSUPPORTED;
    }
  }

  // an int3 to have any stray labels point here
  V(a.int3());

  // we use kData because we want to align with int3-s
  V(a.align(AlignMode::kData, 8));

  a.bind(cip_stubs);

  for (const auto target_idx: control_flow_targets)
    if (!holder.isLabelBound(labels[target_idx]))
      return AMX_MALFORMED_CODE;

  for (const auto& label: labels)
  {
    if (holder.isLabelBound(label))
      V(a.jmp(label));
    else
      V(a.int3());

    V(a.align(AlignMode::kData, 8));
  }

  V(amx->runtime._add(&amx->cod, &holder));
  amx->cip_stub_base = (char*)amx->cod + holder.labelOffset(cip_stubs);
  amx->cip_count = count;

  return AMX_SUCCESS;
}
