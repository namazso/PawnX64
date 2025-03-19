/**
 * @file amx.h
 * @brief Header for the AMX abstract virtual machine.
 * @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
 *            This Source Code Form is subject to the terms of the Mozilla
 *            Public License, v. 2.0. If a copy of the MPL was not distributed
 *            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef AMX_H_
#define AMX_H_
#include <stdint.h>

#ifdef __cplusplus
#define AMX_EXTERN_C_BEGIN extern "C" {
#define AMX_EXTERN_C_END }
#else
#define AMX_EXTERN_C_BEGIN
#define AMX_EXTERN_C_END
#endif

#ifndef AMX_STATIC
#if defined(_MSC_VER)
#ifdef amx64_EXPORTS
#define AMX_EXPORT __declspec(dllexport)
#else
#define AMX_EXPORT __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#ifdef amx64_EXPORTS
#define AMX_EXPORT __attribute__((visibility("default")))
#else
#define AMX_EXPORT
#endif
#else
#define AMX_EXPORT
#endif
#else
#define AMX_EXPORT
#endif

// yes this is compiler specific, but every major compiler has it
#if defined __has_include
#if __has_include(<unistd.h>)
#define AMX_POSIX 1
#endif
#endif

#if !defined(AMX_POSIX) && (defined(__unix__) || defined(__APPLE__))
#define AMX_POSIX 1
#endif

AMX_EXTERN_C_BEGIN

struct amx;

typedef uint64_t amx_cell;

enum amx_status
{
  AMX_SUCCESS = 0,
  AMX_OUT_OF_RESOURCES,
  AMX_ACCESS_VIOLATION,
  AMX_DIVIDE_BY_ZERO,
  AMX_NATIVE_ERROR,
  AMX_RUNTIME_ERROR,
  AMX_NOT_AN_ENTRY_POINT,
  AMX_MALFORMED_CODE,
  AMX_UNSUPPORTED,
  AMX_COMPILE_ERROR,
  AMX_INVALID_ARGUMENT,

  // loader errors

  AMX_LOADER_MALFORMED_FILE = 0x1000,
  AMX_LOADER_UNKNOWN_NATIVE
};

/**
 * Allocate a new instance.
 * @return The new instance if succeeded, @c NULL if out of resources.
 */
AMX_EXPORT struct amx* amx_alloc();

/**
 * Free an instance.
 * @param amx The instance to free. References to this are invalid after calling thins function.
 */
AMX_EXPORT void amx_free(struct amx* amx);

/**
 * Enable level 1 debugging, storing @c CIP value in R8 after every instruction. Low overhead due to dead store elimination.
 */
#define AMX_CODEGEN_CONTROL_DEBUG1 (uint64_t)(1ull << 0)

/**
 * Enable level 2 debugging, which calls the installed debug callback after every instruction.
 */
#define AMX_CODEGEN_CONTROL_DEBUG2 (uint64_t)(1ull << 1)

/**
 * Enable maximum call depth - VM will halt on reaching this, instead of bringing down the whole process.
 */
#define AMX_CODEGEN_CONTROL_CALL_DEPTH (uint64_t)(1ull << 2)

/**
 * This function allows translating native indexes in the code to other indexes that the native callback recognizes.
 */
typedef amx_cell (*amx_native_index_translator)(void* userparam, struct amx* amx, amx_cell idx);

/**
 * Loads code into an instance.
 * @param amx The instance.
 * @param code The buffer holding the contents of the code section.
 * @param count The size of the code buffer, in cells.
 * @param codegen_control Code generation flags.
 * @param translator Translator function.
 * @param userparam Parameter passed to translator function.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_code_load(
  struct amx* amx,
  const amx_cell* code,
  amx_cell count,
  uint64_t codegen_control,
  amx_native_index_translator translator,
  void* userparam);

/**
 * Frees code loaded into an instance.
 * @param amx The instance.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_code_free(struct amx* amx);

/**
 * Read a cell from the memory of an instance.
 * @param amx The instance.
 * @param va Virtual address to read from. Must be cell aligned.
 * @param out The read value.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_cell_read(struct amx* amx, amx_cell va, amx_cell* out);

/**
 * Write a cell to the memory of an instance.
 * @param amx The instance.
 * @param va Virtual address to write to. Must be cell aligned.
 * @param val The value to write.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_cell_write(struct amx* amx, amx_cell va, amx_cell val);

/**
 * A size of a page in the interpreter.
 */
#define AMX_PAGE_SIZE (amx_cell)(0x1000)

/**
 * Allocate pages of memory in the data section of an instance.
 * @param amx The instance.
 * @param va Virtual address. Must be @c AMX_PAGE_SIZE aligned.
 * @param size Size to allocate in bytes. Must be multiple of @c AMX_PAGE_SIZE.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_mem_alloc(struct amx* amx, amx_cell va, amx_cell size);

/**
 * Free pages of memory in the data section of an instance.
 * @param amx The instance.
 * @param va Virtual address. Must be @c AMX_PAGE_SIZE aligned.
 * @param size Size to free in bytes. Must be multiple of @c AMX_PAGE_SIZE.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_mem_free(struct amx* amx, amx_cell va, amx_cell size);

/**
 * Validate and translate a span in the instance's address space to a real world pointer.
 * @param amx The instance.
 * @param va Virtual address. Must be cell aligned.
 * @param size Size in cells.
 * @return @c NULL if the span is not completely allocated, a pointer to an array of @c count size otherwise.
 */
AMX_EXPORT amx_cell* amx_mem_translate(struct amx* amx, amx_cell va, amx_cell count);

enum amx_access_violation_behavior
{
  /**
   * Terminate execution.
   */
  AMX_AV_TERMINATE,

  /**
   * Allocate memory at the place of violation and retry execution.
   */
  AMX_AV_ALLOCATE
};

/**
 * Sets behavior when the vm code touches invalid memory.
 * @param amx The instance.
 * @param behavior Behavior, one of @c amx_access_violation_behavior.
 */
AMX_EXPORT void amx_mem_set_access_violation_behavior(struct amx* amx, enum amx_access_violation_behavior behavior);

enum amx_register
{
  AMX_PRI,
  AMX_ALT,
  AMX_FRM,// 32 bit
  AMX_STK,// 32 bit
  AMX_HEA,// 32 bit
#ifdef AMX_EXPOSE_DANGEROUS_FEATURES
  AMX_DAT,// use amx_cell_{read|write} instead
#endif
  // AMX_CIP, // not implemented
  // AMX_COD, // not implemented
  // AMX_STP, // not implemented
};

/**
 * Read a register of an instance.
 * @param amx The instance.
 * @param reg The register.
 * @return The value of the register.
 */
AMX_EXPORT amx_cell amx_register_read(struct amx* amx, enum amx_register reg);

/**
 * Write a register of an instance.
 * @param amx The instance.
 * @param reg The register.
 * @param val The value to write.
 */
AMX_EXPORT void amx_register_write(struct amx* amx, enum amx_register reg, amx_cell val);

/**
 * Sets an instance-specific arbitrary user data that can be retrieved later.
 * @param amx The instance.
 * @param userdata Arbitrary user data.
 */
AMX_EXPORT void amx_userdata_set(struct amx* amx, void* userdata);

/**
 * Gets the instance-specific arbitrary user data that was set earlier.
 * @param amx The instance.
 * @return The user data.
 */
AMX_EXPORT void* amx_userdata_get(const struct amx* amx);

/**
 * Sets maximum call depth of an instance, if @c AMX_CODEGEN_CONTROL_CALL_DEPTH is used.
 * @param amx The instance.
 * @param max_count Count of nested calls allowed.
 */
AMX_EXPORT void amx_max_call_depth_set(struct amx* amx, amx_cell max_count);

/**
 * The callback that is called when a native is invoked by the vm code. Returns 0 on success.
 */
typedef int (*amx_native_callback)(struct amx*, amx_cell idx);

/**
 * Set the native callback.
 * @param amx The instance.
 * @param callback The callback to call.
 */
AMX_EXPORT void amx_native_callback_set(struct amx* amx, amx_native_callback callback);

/**
 * The callback that is called before every instruction. Only used if code was loaded with @c AMX_CODEGEN_CONTROL_DEBUG2.
 */
typedef void (*amx_debug_callback)(struct amx*, amx_cell cip);

/**
 * Set the debug callback.
 * @param amx The instance.
 * @param callback The callback to call.
 */
AMX_EXPORT void amx_debug_callback_set(struct amx* amx, amx_debug_callback callback);

/**
 * Start running from a certain @c CIP.
 * @param amx The instance.
 * @param cip Entry point.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_run(struct amx* amx, amx_cell cip);

/**
 * Push a value on top of the stack.
 * @param amx The instance.
 * @param v Value to push.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_push(struct amx* amx, amx_cell v);

/**
 * Push values on top of the stack.
 * @param amx The instance.
 * @param v Values to push.
 * @param count Count of values.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_push_n(struct amx* amx, const amx_cell* v, amx_cell count);

/**
 * Call a 0 argument function at a certain @c CIP.
 * @param amx The instance.
 * @param cip Function entry point.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_call(struct amx* amx, amx_cell cip);

/**
 * Call a function at a certain @c CIP.
 * @param amx The instance.
 * @param cip Function entry point.
 * @param argc Arguments count.
 * @param argv Arguments array, right to left.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_call_n(struct amx* amx, amx_cell cip, amx_cell argc, const amx_cell* argv);

/**
 * Call a function at a certain @c CIP.
 * @param amx The instance.
 * @param cip Function entry point.
 * @param argc Arguments count.
 * @param ... Arguments.
 * @return @c AMX_SUCCESS on success, error code otherwise.
 */
AMX_EXPORT enum amx_status amx_call_v(struct amx* amx, amx_cell cip, amx_cell argc, ...);

/**
 * Get the length of a null terminated unpacked string at @p va.
 * @param amx The instance.
 * @param va The start of the string.
 * @return Length of the string in characters if valid, -1 otherwise.
 */
AMX_EXPORT int64_t amx_strlen(struct amx* amx, amx_cell va);

/**
 * Get the length of a null terminated packed string at @p va.
 * @param amx The instance.
 * @param va The start of the string.
 * @return Length of the string in characters if valid, -1 otherwise.
 */
AMX_EXPORT int64_t amx_pstrlen(struct amx* amx, amx_cell va);

#if defined(AMX_POSIX)

#include <signal.h>

/**
 * (POSIX only) Signal handler that you must call when a SIGFPE, SIGSEGV, SIGBUS or SIGTRAP signal is received
 * by the current process.
 * @param signo Signal number.
 * @param info The reason why the signal was generated.
 * @param context The receiving thread context.
 * @return Nonzero if the signal was handled, zero otherwise.
 * @warning Chaining to further signal handlers is the responsibility of the signal handler you implement.
 */
AMX_EXPORT int amx_handle_signal(int signo, siginfo_t* info, void* context);

#endif

AMX_EXTERN_C_END

#endif
