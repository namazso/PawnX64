/**
* @file signalmgr.h
* @brief Header for signal management library for POSIX platforms.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#ifndef SIGNALMGR_H_
#define SIGNALMGR_H_
#include <signal.h>

#ifdef __cplusplus
#define SIGNALMGR_EXTERN_C_BEGIN extern "C" {
#define SIGNALMGR_EXTERN_C_END }
#else
#define SIGNALMGR_EXTERN_C_BEGIN
#define SIGNALMGR_EXTERN_C_END
#endif

#ifndef SIGNALMGR_STATIC
#if defined(__GNUC__)
#ifdef signalmgr_EXPORTS
#define SIGNALMGR_EXPORT __attribute__((visibility("default")))
#else
#define SIGNALMGR_EXPORT
#endif
#else
#define SIGNALMGR_EXPORT
#endif
#else
#define SIGNALMGR_EXPORT
#endif

SIGNALMGR_EXTERN_C_BEGIN

/**
 * Like a sigaction handler with SA_SIGINFO. Returns nonzero if signal was handled, zero if not.
 */
typedef int (*signalmgr_signal_handler)(int signo, siginfo_t* info, void* context);

/**
 * Register an optional signal handler for @p signo.
 * @param signo The signal number.
 * @param handler The handler function.
 */
SIGNALMGR_EXPORT void signalmgr_register_signal(int signo, signalmgr_signal_handler handler);

/**
 * Unregister an optional signal handler for @p signo.
 * @param signo The signal number.
 * @param handler The handler function.
 */
SIGNALMGR_EXPORT void signalmgr_unregister_signal(int signo, signalmgr_signal_handler handler);

SIGNALMGR_EXTERN_C_END

#endif