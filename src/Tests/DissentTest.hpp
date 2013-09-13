#ifndef DISSENT_TEST_H_GUARD
#define DISSENT_TEST_H_GUARD

#define TEST_RANGE_MIN 6
#define TEST_RANGE_MAX 12

#include <qcoreapplication.h>

#include <gtest/gtest.h>

#include "Dissent.hpp"
#include "Mock.hpp"
#include "MockEdgeHandler.hpp"
#include "MockSender.hpp"
#include "MockSource.hpp"
#include "RpcTest.hpp"

static const int TEST_PORT = 55515;

inline bool RunUntil(const SignalCounter &sc, int count)
{
  qint64 next = Timer::GetInstance().VirtualRun();
  while(next != -1 && sc.GetCount() < count) {
    Time::GetInstance().IncrementVirtualClock(next);
    next = Timer::GetInstance().VirtualRun();
  }

  return sc.GetCount() == count;
}

#endif
