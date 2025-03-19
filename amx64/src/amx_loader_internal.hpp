/**
* @file amx_loader_internal.hpp
* @brief Internal header for AMX file format loader.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#pragma once
#include <string>
#include <unordered_map>
#include <vector>

#include "amx_internal.hpp"
#include "amx_loader.h"

struct amx_loader : amx {
  std::vector<std::pair<std::string, amx_loader_native>> natives;
  std::unordered_map<std::string, amx_cell> publics;
  std::unordered_map<std::string, amx_cell> pubvars;
  std::unordered_map<std::string, amx_cell> tags;

  amx_loader();
};
