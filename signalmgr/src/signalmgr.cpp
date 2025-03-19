/**
* @file signalmgr.cpp
* @brief Signal management library for POSIX platforms.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#define _GNU_SOURCE 1
#include "signalmgr.h"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mutex>

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
template<class T, std::size_t N>
constexpr std::size_t arraysize(const T (&array)[N]) noexcept
{
  return N;
}

// POSIX signals
constexpr static int k_signals[] = {
  SIGABRT,
  SIGALRM,
  SIGCHLD,
  SIGCONT,
  SIGFPE,
  SIGHUP,
  SIGILL,
  SIGINT,
  //SIGKILL, // cannot be caught or ignored.
  SIGPIPE,
  SIGQUIT,
  SIGSEGV,
  //SIGSTOP, // cannot be caught or ignored.
  SIGTERM,
  SIGTSTP,
  SIGTTIN,
  SIGTTOU,
  SIGUSR1,
  SIGUSR2,
#ifdef SIGBUS
  SIGBUS,
#endif
#ifdef SIGPROF
  SIGPROF,
#endif
#ifdef SIGSYS
  SIGSYS,
#endif
#ifdef SIGTRAP
  SIGTRAP,
#endif
#ifdef SIGURG
  SIGURG,
#endif
#ifdef SIGVTALRM
  SIGVTALRM,
#endif
#ifdef SIGXCPU
  SIGXCPU,
#endif
#ifdef SIGXFSZ
  SIGXFSZ,
#endif
};

constexpr static size_t k_signal_count = arraysize(k_signals);

constexpr static bool sig_is_terminate_like[] = {
  true, true, false, false, true, true,
  true, true, true, true, true, true,
  false, false, false, true, true, true,
  true, true, true, false, true, true,
  true};

static int find_signal(int signo)
{
  for (int i = 0; i < k_signal_count; ++i)
    if (signo == k_signals[i])
      return i;
  return -1;
}

static struct sigaction sigactions[k_signal_count];

static void call_old_sighandler(int signo, siginfo_t* info, void* context)
{
  const auto sig_idx = find_signal(signo);
  const auto act = &sigactions[sig_idx];

  // We back these up because SA_NODEFER may modify it before call
  void (*sig_sigaction)(int, siginfo_t*, void*) = nullptr;
  void (*sig_handler)(int) = nullptr;
  const auto is_siginfo = (act->sa_flags & SA_SIGINFO) != 0;

  if (is_siginfo)
  {
    if (!act->sa_sigaction)
    {
      // should never happen
      assert(0);
      return;
    }
    else
    {
      sig_sigaction = act->sa_sigaction;
    }
  }
  else
  {
    if (act->sa_handler == SIG_IGN)
    {
      return;
    }
    else if (act->sa_handler == SIG_DFL)
    {
      // Just register back the old one and let the process crash / terminate
      if (sig_is_terminate_like[sig_idx])
        sigaction(signo, act, nullptr);
      return;
    }
    else
    {
      sig_handler = act->sa_handler;
    }
  }

  if (!(act->sa_flags & SA_NODEFER))
    sigaddset(&(act->sa_mask), signo);

  if (act->sa_flags & SA_RESETHAND)
    act->sa_handler = SIG_DFL;

  sigset_t oldmask{};
  sigemptyset(&oldmask);
  pthread_sigmask(SIG_SETMASK, &(act->sa_mask), &oldmask);

  if (is_siginfo)
    sig_sigaction(signo, info, context);
  else
    sig_handler(signo);

  pthread_sigmask(SIG_SETMASK, &oldmask, nullptr);
}

struct list_entry {
  struct list_entry* next{};
  signalmgr_signal_handler handler{};
};

struct list_head {
  struct list_entry* first{};
  spin_lock lock;
};

static struct list_head signal_handlers[k_signal_count];

static void my_sighandler(int signo, siginfo_t* info, void* context)
{
  // copy errno as per BSD manpage
  const auto errno_copy = errno;
  const auto idx = find_signal(signo);
  const auto head = &signal_handlers[idx];
  bool handled = false;
  {
    std::lock_guard<spin_lock> guard(head->lock);
    struct list_entry* it = head->first;
    while (it)
    {
      if (it->handler(signo, info, context))
      {
        handled = true;
        break;
      }
      it = it->next;
    }
  }
  errno = errno_copy;
  if (!handled)
    call_old_sighandler(signo, info, context);
}

void signalmgr_register_signal(int signo, signalmgr_signal_handler handler)
{
  const auto idx = find_signal(signo);
  if (idx == -1)
    return;
  const auto head = &signal_handlers[idx];
  const auto entry = (struct list_entry*)malloc(sizeof(struct list_entry));
  memset(entry, 0, sizeof(*entry));
  entry->handler = handler;
  {
    std::lock_guard<spin_lock> guard(head->lock);
    entry->next = head->first;
    head->first = entry;
  }
}

void signalmgr_unregister_signal(int signo, signalmgr_signal_handler handler)
{
  const auto idx = find_signal(signo);
  if (idx == -1)
    return;
  const auto head = &signal_handlers[idx];
  list_entry* to_remove = nullptr;
  {
    std::lock_guard<spin_lock> guard(head->lock);
    auto next_of_previous = &head->first;
    auto it = head->first;
    while (it)
    {
      if (it->handler == handler)
      {
        to_remove = it;
        *next_of_previous = it->next;
        break;
      }
      next_of_previous = &it->next;
      it = it->next;
    }
  }
  assert(to_remove);
  free(to_remove);
}

static void register_signals()
{
  for (size_t i = 0; i < k_signal_count; ++i)
  {
    struct sigaction sa {
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &my_sighandler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(k_signals[i], &sa, &sigactions[i]);
  }
}

// this is not POSIX but most BSDs, Linux and Mac have it
static void make_permanently_loaded()
{
  static char a_variable_in_the_module;

  typedef struct
  {
    const char* dli_fname;
    void* dli_fbase;
    const char* dli_sname;
    void* dli_saddr;
    void* dli_reserved[40];// just to make sure
  } amx_Dl_info;

  using amx_dladdr_t = int (*)(const void* address, amx_Dl_info* info);

  const auto p_dladdr = (amx_dladdr_t)dlsym(nullptr, "dladdr");

  if (p_dladdr)
  {
    amx_Dl_info dl_info;
    memset(&dl_info, 0, sizeof(dl_info));
    int res = p_dladdr(&a_variable_in_the_module, &dl_info);
    assert(res && dl_info.dli_fname);
    int flags = RTLD_NOW;
#ifdef RTLD_NODELETE
    flags |= RTLD_NODELETE;
#endif
    // Leak a reference to ourselves
    void* me = dlopen(dl_info.dli_fname, flags);
    assert(me);
  }
}

struct construct_destruct_module {
  construct_destruct_module();
  ~construct_destruct_module();
};

static construct_destruct_module module;

construct_destruct_module::construct_destruct_module()
{
  make_permanently_loaded();

  register_signals();
}
construct_destruct_module::~construct_destruct_module()
{
  (void)0;
}
