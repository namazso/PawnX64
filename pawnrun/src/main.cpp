/**
* @file main.cpp
* @brief pawnrun program.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include <amx.h>
#include <amx_loader.h>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <vector>

#ifdef AMX_POSIX
#include <signalmgr.h>
void register_signal_handlers()
{
  signalmgr_register_signal(SIGFPE, &amx_handle_signal);
  signalmgr_register_signal(SIGSEGV, &amx_handle_signal);
  signalmgr_register_signal(SIGTRAP, &amx_handle_signal);
}
#else
void register_signal_handlers()
{
}
#endif

bool read_all(const char* path, std::vector<uint8_t>& data)
{
  data.clear();
  std::ifstream is(path, std::ios::binary);
  if (!is.good() || !is.is_open())
    return false;
  is.seekg(0, std::ifstream::end);
  data.resize((size_t)is.tellg());
  is.seekg(0, std::ifstream::beg);
  is.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size());
  if (!is.good() || !is.is_open())
    return false;
  return true;
}

bool extract_string(std::string& out, amx* amx, amx_cell va)
{
  out.clear();
  while (true)
  {
    amx_cell cell{};
    if (AMX_SUCCESS != amx_cell_read(amx, va, &cell))
      return false;
    if (!cell)
      break;
    out += (char)cell;
    va += sizeof(amx_cell);
  }
  return true;
}

int main(int argc, char** argv)
{
  register_signal_handlers();
  if (argc < 2)
  {
    fprintf(stderr, "No input given.\nUsage: %s <amx file>\n", argv[0]);
    return -1;
  }
  const auto loader = amx_loader_alloc();
  assert(loader);

  std::vector<uint8_t> file;
  if (!read_all(argv[1], file))
  {
    fprintf(stderr, "File %s unreadable.\n", argv[1]);
    return -2;
  }

  amx_loader_register_native(
    loader,
    "my_print",
    [](struct amx_loader* loader, struct amx* amx, void* userdata, amx_cell* return_value, amx_cell argc, const amx_cell* argv) -> int {
      std::string text;
      if (!extract_string(text, amx, argv[0]))
        return 0;
      printf("%s\n", text.c_str());
      return 1;
    });

  amx_cell main{};

  constexpr uint64_t codegen_control =
#ifdef NDEBUG
    0
#else
    AMX_CODEGEN_CONTROL_DEBUG1 | AMX_CODEGEN_CONTROL_DEBUG2
#endif
    ;

  auto status = amx_loader_load(loader, file.data(), file.size(), &main, codegen_control);
  if (status != AMX_SUCCESS)
  {
    fprintf(stderr, "File %s cannot be loaded: %X.\n", argv[1], status);
    return -3;
  }

  const auto my_amx = amx_loader_get_amx(loader);

  if (main)
    status = amx_call(my_amx, main);
  else
    printf("No main function...\n");

  if (status != AMX_SUCCESS)
    printf("main failed with %d\n", status);

  amx_loader_free(loader);
  return 0;
}
