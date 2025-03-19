/**
* @file main.cpp
* @brief amx64 tests.
* @copyright Copyright (C) 2022  namazso <admin@namazso.eu>
*            This Source Code Form is subject to the terms of the Mozilla
*            Public License, v. 2.0. If a copy of the MPL was not distributed
*            with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "gtest/gtest.h"
#include <amx.h>
#include <amx_loader.h>

#ifdef AMX_POSIX
#include <signalmgr.h>
static struct SignalAutoRegister {
  SignalAutoRegister()
  {
    signalmgr_register_signal(SIGFPE, &amx_handle_signal);
    signalmgr_register_signal(SIGSEGV, &amx_handle_signal);
    signalmgr_register_signal(SIGBUS, &amx_handle_signal);
    signalmgr_register_signal(SIGTRAP, &amx_handle_signal);
  }
  ~SignalAutoRegister() = default;
} _signal_auto_register;
#endif

// test.amx (test.p compiled)
#include "test_amx.h"

class AmxTest : public ::testing::Test
{
protected:
  amx_loader* _ldr;
  amx* _amx;

  void SetUp() override
  {
    _ldr = amx_loader_alloc();
    ASSERT_NE(_ldr, nullptr);
    _amx = amx_loader_get_amx(_ldr);
    ASSERT_NE(_amx, nullptr);
    amx_cell main{};
    const auto status = amx_loader_load(_ldr, TEST_AMX, sizeof(TEST_AMX), &main, AMX_CODEGEN_CONTROL_CALL_DEPTH);
    ASSERT_EQ(status, AMX_SUCCESS);
  }

  void TearDown() override
  {
    amx_loader_free(_ldr);
  }
};

#define TEST_PAWN(name, expected_result, expected_retval)        \
  TEST_F(AmxTest, name)                                          \
  {                                                              \
    const auto fn = amx_loader_find_public(_ldr, "test_" #name); \
    EXPECT_NE(fn, 0);                                            \
    amx_register_write(_amx, AMX_PRI, 0xCCCCCCCCCCCCCCCC);       \
    const auto result = amx_call(_amx, fn);                      \
    const auto retval = amx_register_read(_amx, AMX_PRI);        \
    EXPECT_EQ(result, expected_result);                          \
    if (result == AMX_SUCCESS)                                   \
      EXPECT_EQ(retval, expected_retval);                        \
  }

TEST_PAWN(Arithmetic, AMX_SUCCESS, 1);
TEST_PAWN(Indirect, AMX_SUCCESS, 1);
TEST_PAWN(Switch, AMX_SUCCESS, 1);
TEST_PAWN(SwitchBreak, AMX_SUCCESS, 1);
TEST_PAWN(SwitchDefault, AMX_SUCCESS, 1);
TEST_PAWN(SwitchOnlyDefault, AMX_SUCCESS, 1);
TEST_PAWN(Array, AMX_SUCCESS, 1);
TEST_PAWN(ArrayOverindex, AMX_ACCESS_VIOLATION, 0);
TEST_PAWN(Div, AMX_SUCCESS, 1);
TEST_PAWN(DivZero, AMX_DIVIDE_BY_ZERO, 0);
TEST_PAWN(VarArgs, AMX_SUCCESS, 1);
TEST_PAWN(Statics, AMX_SUCCESS, 12);
TEST_PAWN(Packed, AMX_SUCCESS, 1);
TEST_PAWN(GotoStackFixup, AMX_SUCCESS, 4105);
TEST_PAWN(Bounds, AMX_SUCCESS, 6);
TEST_PAWN(StackOverflow, AMX_NATIVE_ERROR, 0);
