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

inline void RunUntil(const SignalCounter &sc, int count)
{
  Time &time = Time::GetInstance();
  Timer &timer = Timer::GetInstance();
  while(sc.GetCount() < count) {
    time.IncrementVirtualClock(timer.VirtualRun());
  }
}

#endif
