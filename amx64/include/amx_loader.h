/**
* @file amx_loader.h
* @brief Header for the AMX file format loader.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#ifndef AMX_LOADER_H_
#define AMX_LOADER_H_
#include "amx.h"

AMX_EXTERN_C_BEGIN

struct amx_loader;

/**
 * Allocate a new loader instance.
 * @return The new loader instance if succeeded, @c NULL if out of resources.
 */
AMX_EXPORT struct amx_loader* amx_loader_alloc();

/**
 * Free a loader instance.
 * @param loader The instance to free. References to this are invalid after calling thins function.
 */
AMX_EXPORT void amx_loader_free(struct amx_loader* loader);

/**
 * Get the @c amx instance associated with this loader.
 * @param loader The loader instance.
 * @return The @c amx instance.
 */
AMX_EXPORT struct amx* amx_loader_get_amx(struct amx_loader* loader);

/**
 * The callback type for a native.
 */
typedef int (*amx_loader_native)(
  struct amx_loader* loader,
  struct amx* amx,
  void* userdata,
  amx_cell* return_value,
  amx_cell argc,
  const amx_cell* argv);

/**
 * Registers a native with this loader instance.
 * @param loader The loader instance.
 * @param name Name of the native.
 * @param callback The native callback.
 */
AMX_EXPORT void amx_loader_register_native(struct amx_loader* loader, const char* name, amx_loader_native callback);

/**
 * Finds a public defined in the loaded module.
 * @param loader The loader instance.
 * @param name Name of the public.
 * @return The @c CIP of the function if found, 0 otherwise.
 */
AMX_EXPORT amx_cell amx_loader_find_public(struct amx_loader* loader, const char* name);

/**
 * Finds a pubvar defined in the loaded module.
 * @param loader The loader instance.
 * @param name Name of the pubvar.
 * @return The virtual address of the variable if found, ~0 otherwise.
 */
AMX_EXPORT amx_cell amx_loader_find_pubvar(struct amx_loader* loader, const char* name);

/**
 * Finds a tag defined in the loaded module.
 * @param loader The loader instance.
 * @param name Name of the tag.
 * @return The id of the tag if found, ~0 otherwise.
 */
AMX_EXPORT amx_cell amx_loader_find_tag(struct amx_loader* loader, const char* name);

/**
 * Load an AMX module from memory.
 * @param loader The loader instance.
 * @param bytes Bytes of the AMX file.
 * @param size Size of the AMX file.
 * @param main @c CIP of main function, 0 if none.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_loader_load(
  struct amx_loader* loader,
  const uint8_t* bytes,
  amx_cell size,
  amx_cell* main,
  uint64_t codegen_control);

AMX_EXTERN_C_END

#endif