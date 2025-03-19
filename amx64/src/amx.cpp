/**
* @file amx.cpp
* @brief AMX abstract virtual machine, platform independent bits.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "amx_internal.hpp"
#include "amx.h"

#include <cstdarg>
#include <cstddef>
#include <exception>

static_assert(sizeof(void*) == sizeof(uint64_t), "Only x64 systems are supported");

amx_cell amx_register_read(amx* amx, enum amx_register reg)
{
  switch (reg)
  {
  case AMX_PRI:
    return amx->pri;
  case AMX_ALT:
    return amx->alt;
  case AMX_FRM:
    return amx->frm;
  case AMX_STK:
    return amx->stk;
  case AMX_HEA:
    return amx->hea;
  case AMX_DAT:
    return (amx_cell)amx->dat;
  }
  return 0;
}

void amx_register_write(amx* amx, enum amx_register reg, amx_cell val)
{
  switch (reg)
  {
  case AMX_PRI:
    amx->pri = val;
    break;
  case AMX_ALT:
    amx->alt = val;
    break;
  case AMX_FRM:
    amx->frm = (uint32_t)val;
    break;
  case AMX_STK:
    amx->stk = (uint32_t)val;
    break;
  case AMX_HEA:
    amx->hea = (uint32_t)val;
    break;
  case AMX_DAT:// not writeable
  default:
    break;
  }
}

void amx_mem_set_access_violation_behavior(amx* amx, enum amx_access_violation_behavior behavior)
{
  amx->av_behavior = behavior;
}

void amx_userdata_set(amx* amx, void* userdata)
{
  amx->userdata = userdata;
}

void* amx_userdata_get(const amx* amx)
{
  return amx->userdata;
}

void amx_native_callback_set(amx* amx, amx_native_callback callback)
{
  amx->native_callback = callback;
}

void amx_debug_callback_set(amx* amx, amx_debug_callback callback)
{
  amx->debug_callback = callback;
}

amx_status amx_run(amx* amx, amx_cell cip)
{
  if (cip & 7)
    return AMX_NOT_AN_ENTRY_POINT;
  const auto idx = cip / sizeof(amx_cell);
  if (idx >= amx->cip_count)
    return AMX_NOT_AN_ENTRY_POINT;
  const auto ip = (char*)amx->cip_stub_base + idx * sizeof(amx_cell);
  return amx_enter(amx, ip);
}

amx_status amx_push(amx* amx, amx_cell v)
{
  amx->stk -= sizeof(amx_cell);
  return amx_cell_write(amx, amx->stk, v);
}

amx_status amx_push_n(amx* amx, const amx_cell* v, amx_cell count)
{
  for (size_t i = 0; i < count; ++i)
  {
    const auto result = amx_push(amx, v[i]);
    if (result != AMX_SUCCESS)
      return result;
  }
  return AMX_SUCCESS;
}

amx_status amx_call_n(amx* amx, amx_cell cip, amx_cell argc, const amx_cell* argv)
{
  // calls shouldn't modify these
  const auto stk = amx->stk;
  const auto frm = amx->frm;

  auto status = amx_push_n(amx, argv, argc);
  if (status != AMX_SUCCESS)
    return status;
  status = amx_push(amx, argc * sizeof(amx_cell));
  if (status != AMX_SUCCESS)
    return status;
  amx_push(amx, 0);// return CIP
  status = amx_run(amx, cip);

  amx->stk = stk;
  amx->frm = frm;

  return status;
}

amx_status amx_call(amx* amx, amx_cell cip)
{
  return amx_call_n(amx, cip, 0, nullptr);
}

amx_status amx_call_v(amx* amx, amx_cell cip, amx_cell argc, ...)
{
  amx_cell argv[256];
  if (argc >= 256)
    return AMX_OUT_OF_RESOURCES;
  va_list args;
  va_start(args, argc);
  for (size_t i = 0; i < argc; ++i)
    argv[argc - 1 - i] = va_arg(args, amx_cell);
  va_end(args);
  return amx_call_n(amx, cip, argc, argv);
}

amx::amx()
{
  dat = amx_mem_reserve();
  if (dat == nullptr)
    throw std::bad_alloc();
  amx_instance_register(this);

  // we do a read we know will fail to early crash UNIX users who didn't properly set up amx_handle_signal
  amx_cell unused;
  amx_cell_read(this, 0, &unused);
}

amx::~amx()
{
  amx_instance_unregister(this);
  amx_mem_release(dat);
  if (cod)
    amx_code_free(this);
}

amx* amx_alloc()
{
  try
  {
    return new struct amx;
  }
  catch (std::bad_alloc& e)
  {
  }
  return nullptr;
}

void amx_free(amx* amx)
{
  delete amx;
}

amx_status amx_code_free(amx* amx)
{
  // C convention: calling free on nullptr is legal.
  if (amx)
  {
    if (amx->cod)
      amx->runtime._release(amx->cod);
    amx->cod = nullptr;
    amx->cip_stub_base = nullptr;
    amx->cip_count = 0;
  }
  return AMX_SUCCESS;
}

amx_cell* amx_mem_translate(struct amx* amx, amx_cell va, amx_cell count)
{
  if ((va & AMX_MISALIGN_MASK) || va >= AMX_ADDRESS_SPACE_SIZE)
    return nullptr;
  if (count >= AMX_ADDRESS_SPACE_SIZE || count * sizeof(amx_cell) >= AMX_ADDRESS_SPACE_SIZE)
    return nullptr;
  if ((va + count * sizeof(amx_cell)) >= AMX_ADDRESS_SPACE_SIZE)
    return nullptr;
  const auto first_va = va & AMX_PAGE_MASK;
  const auto last_va = (va + count * sizeof(amx_cell)) & AMX_PAGE_MASK;
  for (amx_cell i = first_va; i != last_va; i += AMX_PAGE_SIZE)
  {
    amx_cell out;
    if (amx_cell_read(amx, va, &out) != AMX_SUCCESS)
      return nullptr;
  }
  return (amx_cell*)((char*)amx->dat + va);
}

int64_t amx_strlen(struct amx* amx, amx_cell va)
{
  if ((va & AMX_MISALIGN_MASK) || va >= AMX_ADDRESS_SPACE_SIZE)
    return -1;
  amx_cell read;
  if (AMX_SUCCESS != amx_cell_read(amx, va, &read))
    return -1;
  int64_t i = 0;
  while (true)
  {
    const auto address = va + i * sizeof(amx_cell);
    if ((address & AMX_PAGE_OFFSET_MASK) == 0){
      if (AMX_SUCCESS != amx_cell_read(amx, address, &read))
        return -1;
    } else {
      read = *(amx_cell*)((char*)amx->dat + address);
    }
    if (read == 0)
      break;
    i += 1;
  }
  return i;
}

int64_t amx_pstrlen(struct amx* amx, amx_cell va)
{
  if (va >= AMX_ADDRESS_SPACE_SIZE)
    return -1;
  amx_cell read;
  if (AMX_SUCCESS != amx_cell_read(amx, va & AMX_ALIGN_MASK, &read))
    return -1;
  int64_t i = 0;
  while (true)
  {
    const auto address = va + i;
    char read_char = 0;
    if ((address & AMX_PAGE_OFFSET_MASK) == 0){
      if (AMX_SUCCESS != amx_cell_read(amx, address, &read))
        return -1;
      read_char = (char)(uint8_t)read;
    } else {
      read_char = *((char*)amx->dat + address);
    }
    if (read_char == 0)
      break;
    i += 1;
  }
  return i;
}

void amx_max_call_depth_set(struct amx* amx, amx_cell max_count)
{
  amx->max_stack_size = max_count * 0x10;
}

void amx_empty_debug_callback(struct amx*, amx_cell)
{
}
