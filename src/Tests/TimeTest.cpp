#include <QDebug>
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace DU = Dissent::Utils;

  TEST(Time, CheckRealTime)
  {
    DU::Time &time = DU::Time::GetInstance();
    time.UseRealTime();
    EXPECT_TRUE(time.UsingRealTime());
    time.UseRealTime();
    qint64 now0 = time.MSecsSinceEpoch();
    DU::Sleeper::MSleep(1);
    qint64 now1 = time.MSecsSinceEpoch();
    EXPECT_LT(now0, now1);
  }

  TEST(Time, CheckVirtualTime)
  {
    DU::Time &time = DU::Time::GetInstance();
    time.UseVirtualTime();
    qint64 now0 = time.MSecsSinceEpoch();
    qint64 now1 = time.MSecsSinceEpoch();
    EXPECT_EQ(now0, now1);
  }

  class MockTimerCallback {
    public:
      int value;

      MockTimerCallback(int value) : value(value)
      {
      }

      void Set(const int &nv)
      {
        value = nv;
      }
  };

  TEST(Time, CheckTimerEventRealIncreasing)
  {
    DU::Timer &timer = DU::Timer::GetInstance();
    timer.UseRealTime();
    int sleep = 5;
    MockTimerCallback mtc = MockTimerCallback(2);
    DU::TimerMethod<MockTimerCallback, int> *cb0 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    DU::TimerEvent qc0 = timer.QueueCallback(cb0, sleep / 2, sleep * 3);
    MockExec();
    DU::Sleeper::MSleep(sleep / 8);
    MockExec();
    EXPECT_EQ(2, mtc.value);
    DU::Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    DU::TimerMethod<MockTimerCallback, int> *cb1 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    DU::TimerEvent qc1 = timer.QueueCallback(cb1, sleep / 2);
    DU::Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(6, mtc.value);
    DU::Sleeper::MSleep(sleep * 3);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    qc0.Stop();
    qc1.Stop();
  }

  TEST(Time, CheckTimerEventRealDecreasing)
  {
    DU::Timer &timer = DU::Timer::GetInstance();
    timer.UseRealTime();
    int sleep = 5;
    MockTimerCallback mtc = MockTimerCallback(2);
    DU::TimerMethod<MockTimerCallback, int> *cb0 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    DU::TimerMethod<MockTimerCallback, int> *cb1 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    DU::TimerEvent qc0 = timer.QueueCallback(cb0, sleep / 2 + sleep);
    DU::TimerEvent qc1 = timer.QueueCallback(cb1, sleep / 2);
    MockExec();
    DU::Sleeper::MSleep(sleep / 8);
    MockExec();
    EXPECT_EQ(2, mtc.value);
    DU::Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    DU::Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(6, mtc.value);
    qc0.Stop();
    qc1.Stop();
  }

  TEST(Time, CheckTimerEventVirtual)
  {
    DU::Timer &timer = DU::Timer::GetInstance();
    timer.UseVirtualTime();
    int sleep = 1000*1000;
    MockTimerCallback mtc = MockTimerCallback(2);
    DU::TimerMethod<MockTimerCallback, int> *cb0 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    DU::TimerMethod<MockTimerCallback, int> *cb1 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 7);
    DU::TimerMethod<MockTimerCallback, int> *cb2 =
      new DU::TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    DU::TimerEvent qc0 = timer.QueueCallback(cb0, sleep * 3);
    DU::TimerEvent qc1 = timer.QueueCallback(cb1, sleep * 5);
    DU::TimerEvent qc2 = timer.QueueCallback(cb2, sleep);

    DU::Time &time = DU::Time::GetInstance();
    qint64 next = timer.VirtualRun();
    EXPECT_EQ(2, mtc.value);

    time.IncrementVirtualClock(next / 2);
    timer.VirtualRun();
    EXPECT_EQ(2, mtc.value);

    time.IncrementVirtualClock(next / 2);
    next = timer.VirtualRun();
    EXPECT_EQ(5, mtc.value);
    time.IncrementVirtualClock(next);
    next = timer.VirtualRun();
    EXPECT_EQ(6, mtc.value);
    time.IncrementVirtualClock(next);
    next = timer.VirtualRun();
    EXPECT_EQ(7, mtc.value);
    qc0.Stop();
    qc1.Stop();
    qc2.Stop();
  }
}
}
