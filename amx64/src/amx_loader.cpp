/**
* @file amx_loader.cpp
* @brief AMX file format loader.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "amx_loader.h"
#include "amx_loader_internal.hpp"
#include <algorithm>

static int loader_callback(struct amx* amx, amx_cell idx)
{
  const auto loader = static_cast<amx_loader*>(amx);// NOLINT(cppcoreguidelines-pro-type-static-cast-downcast)
  amx_cell argc{};
  if (AMX_SUCCESS != amx_cell_read(amx, amx->stk, &argc))
    return 0;
  argc /= sizeof(amx_cell);
  const auto argv_va = amx->stk + sizeof(amx_cell);
  amx_cell* argv{};
  if (argc)
  {
    argv = amx_mem_translate(amx, argv_va, argc);
    if (!argv)
      return 0;
  }
  amx->pri = 0;
  return loader->natives[idx].second(
    loader,
    amx,
    amx->userdata,
    &amx->pri,
    argc,
    argv);
}

amx_loader::amx_loader()
{
  amx_native_callback_set(this, &loader_callback);
}

amx_loader* amx_loader_alloc()
{
  try
  {
    return new struct amx_loader;
  }
  catch (std::bad_alloc& e)
  {
  }
  return nullptr;
}

void amx_loader_free(struct amx_loader* loader)
{
  delete loader;
}

struct amx* amx_loader_get_amx(struct amx_loader* loader)
{
  return loader;
}

void amx_loader_register_native(struct amx_loader* loader, const char* name, amx_loader_native callback)
{
  loader->natives.emplace_back(name, callback);
}

amx_cell amx_loader_find_public(struct amx_loader* loader, const char* name)
{
  const auto found = loader->publics.find(name);
  return found == loader->publics.end() ? 0 : found->second;
}

amx_cell amx_loader_find_pubvar(struct amx_loader* loader, const char* name)
{
  const auto found = loader->pubvars.find(name);
  return found == loader->pubvars.end() ? ~(amx_cell)0 : found->second;
}

amx_cell amx_loader_find_tag(struct amx_loader* loader, const char* name)
{
  const auto found = loader->tags.find(name);
  return found == loader->tags.end() ? ~(amx_cell)0 : found->second;
}

template<typename T>
bool valarray_extract(
  std::vector<T>& out,
  const uint8_t* buf,
  size_t buf_size,
  size_t begin_offset,
  size_t end_offset,
  size_t elem_size = sizeof(T))
{
  out.clear();
  if (elem_size < sizeof(T))
    return false;
  if (begin_offset > buf_size)
    return false;
  if (end_offset > buf_size)
    return false;
  if (end_offset < begin_offset)
    return false;
  const auto arr_size = end_offset - begin_offset;
  if (arr_size % elem_size != 0)
    return false;
  const auto arr_count = arr_size / elem_size;
  out.resize(arr_count);
  for (size_t i = 0; i < arr_count; ++i)
    memcpy(&out[i], &buf[begin_offset + i * elem_size], sizeof(T));
  return true;
}

static bool string_extract(
  std::string& out,
  const uint8_t* buf,
  size_t buf_size,
  size_t begin_offset)
{
  if (begin_offset >= buf_size)
    return false;
  auto end_offset = begin_offset;
  while (end_offset < buf_size && buf[end_offset])
    ++end_offset;
  out = {(const char*)&buf[begin_offset], (const char*)&buf[end_offset]};
  return true;
}

enum amx_status amx_loader_load(struct amx_loader* loader, const uint8_t* bytes, amx_cell size, amx_cell* main, uint64_t codegen_control)
{
  struct amx_file_header {
    uint32_t size;       // size of the image in bytes
    uint16_t magic;      // 0xF1E1 for 64 bit cells
    uint8_t file_version;// currently 11
    uint8_t amx_version; // currently 11
    uint16_t flags;      // combination of amx_file_flag
    uint16_t defsize;    // structure size in natives and publics table
    uint32_t cod;        // file offset to start of code section
    uint32_t dat;        // file offset to end of code section, start of data section
    uint32_t hea;        // file offset to end of data section. (beginning of heap in original impl)
    uint32_t stp;        // top of VA space in original impl. stack top
    uint32_t cip;        // address of main, -1 if none
    uint32_t publics;    // file offset to start of publics table
    uint32_t natives;    // file offset to end of publics table, start of natives table
    uint32_t libraries;  // file offset to end of natives table, start of libraries table
    uint32_t pubvars;    // file offset to end of libraries table, start of pubvars table
    uint32_t tags;       // file offset to end of pubvars table, start of public tags table
    uint32_t nametable;  // file offset to end of overlay table, start of symbol name table
    uint32_t overlays;   // file offset to end of tags table, start of overlay table
  };

  // clang-format off
  enum amx_file_flag : uint32_t
  {
    flag_overlay    = 1 << 0, // function calls use overlays
    flag_debug      = 1 << 1, // symbolic info available
    flag_nochecks   = 1 << 2, // no BOUNDS or BREAK
    flag_sleep      = 1 << 3, // no SLEEP
    flag_crypt      = 1 << 4, // file is encrypted
    flag_dseg_init  = 1 << 5, // code initializes data segment
  };
  // clang-format on

  if (size < sizeof(amx_file_header))
    return AMX_LOADER_MALFORMED_FILE;
  const auto hdr = (const amx_file_header*)bytes;
  if (hdr->size > size || hdr->magic != 0xF1E1)
    return AMX_LOADER_MALFORMED_FILE;
  if (hdr->file_version != 11 || hdr->amx_version != 11)
    return AMX_UNSUPPORTED;
  if (hdr->flags & (flag_overlay | flag_sleep | flag_crypt))
    return AMX_UNSUPPORTED;
  if (hdr->defsize < 8)
    return AMX_UNSUPPORTED;

  std::vector<amx_cell> cod;
  if (!valarray_extract(cod, bytes, size, hdr->cod, hdr->dat))
    return AMX_LOADER_MALFORMED_FILE;
  std::vector<amx_cell> dat;
  if (!valarray_extract(dat, bytes, size, hdr->dat, hdr->hea))
    return AMX_LOADER_MALFORMED_FILE;
  if (hdr->stp < hdr->dat)
    return AMX_LOADER_MALFORMED_FILE;

  struct address_name_pair {
    uint32_t address;
    uint32_t name_offset;
  };

  std::vector<address_name_pair> publics;
  if (!valarray_extract(publics, bytes, size, hdr->publics, hdr->natives, hdr->defsize))
    return AMX_LOADER_MALFORMED_FILE;

  for (const auto& e: publics)
  {
    std::string name;
    if (!string_extract(name, bytes, size, e.name_offset))
      return AMX_LOADER_MALFORMED_FILE;
    if (e.address % sizeof(amx_cell) != 0)
      return AMX_LOADER_MALFORMED_FILE;
    loader->publics[name] = e.address;
  }

  std::vector<address_name_pair> natives;
  if (!valarray_extract(natives, bytes, size, hdr->natives, hdr->libraries, hdr->defsize))
    return AMX_LOADER_MALFORMED_FILE;

  std::unordered_map<amx_cell, amx_cell> native_remap_map;
  for (size_t i = 0; i < natives.size(); ++i)
  {
    std::string name;
    const auto& e = natives[i];
    if (!string_extract(name, bytes, size, e.name_offset))
      return AMX_LOADER_MALFORMED_FILE;
    const auto found = std::find_if(
      begin(loader->natives),
      end(loader->natives),
      [&name](const std::pair<std::string, amx_loader_native>& current) {
        return name == current.first;
      });
    if (found == end(loader->natives))
      return AMX_LOADER_UNKNOWN_NATIVE;
    native_remap_map[i] = found - std::begin(loader->natives);
  }

  // just ignore libraries altogether.
  //if (hdr->libraries != hdr->pubvars)
  //return AMX_UNSUPPORTED;

  std::vector<address_name_pair> pubvars;
  if (!valarray_extract(pubvars, bytes, size, hdr->pubvars, hdr->tags, hdr->defsize))
    return AMX_LOADER_MALFORMED_FILE;

  for (const auto& e: pubvars)
  {
    std::string name;
    if (!string_extract(name, bytes, size, e.name_offset))
      return AMX_LOADER_MALFORMED_FILE;
    if (e.address % sizeof(amx_cell) != 0)
      return AMX_LOADER_MALFORMED_FILE;
    loader->pubvars[name] = e.address;
  }

  std::vector<address_name_pair> tags;
  if (!valarray_extract(tags, bytes, size, hdr->tags, hdr->overlays, hdr->defsize))
    return AMX_LOADER_MALFORMED_FILE;

  for (const auto& e: tags)
  {
    std::string name;
    if (!string_extract(name, bytes, size, e.name_offset))
      return AMX_LOADER_MALFORMED_FILE;
    if (e.address % sizeof(amx_cell) != 0)
      return AMX_LOADER_MALFORMED_FILE;
    loader->tags[name] = e.address;
  }

  // allocate & copy data

  const auto extra_size = (hdr->stp - hdr->hea) + sizeof(amx_cell) - 1;
  const auto needed_size = (dat.size() * sizeof(amx_cell) + extra_size);
  const auto alloc_size = (needed_size | (AMX_PAGE_SIZE - 1)) + 1;

  auto status = amx_mem_alloc(loader, 0, alloc_size);
  if (status != AMX_SUCCESS)
    return status;

  const auto dat_ptr = amx_mem_translate(loader, 0, dat.size());
  if (!dat_ptr)
    return AMX_RUNTIME_ERROR;

  std::copy(begin(dat), end(dat), dat_ptr);

  // allocate stack extra compared to original

  const auto stack_alloc_size = (extra_size | AMX_PAGE_OFFSET_MASK) + 1;
  const auto stp = (amx_cell)0x80000000 - 32;// a bit below 2 GB
  const auto stp_aligned = stp & AMX_PAGE_MASK;

  status = amx_mem_alloc(loader, stp_aligned - stack_alloc_size + AMX_PAGE_SIZE, stack_alloc_size);
  if (status != AMX_SUCCESS)
    return status;

  amx_register_write(loader, AMX_STK, stp);
  amx_register_write(loader, AMX_FRM, stp);
  amx_register_write(loader, AMX_HEA, dat.size() * sizeof(amx_cell));

  // load code

  status = amx_code_load(
    loader,
    cod.data(),
    cod.size(),
    codegen_control,
    [](void* userparam, struct amx* amx, amx_cell idx) -> amx_cell {
      const auto& remap = *(std::unordered_map<amx_cell, amx_cell>*)userparam;
      const auto found = remap.find(idx);
      if (found != end(remap))
        return found->second;
      return (amx_cell)(int64_t)-1;
    },
    &native_remap_map);
  if (status != AMX_SUCCESS)
    return status;

  *main = hdr->cip == (uint32_t)-1 ? 0 : hdr->cip;

  return AMX_SUCCESS;
}