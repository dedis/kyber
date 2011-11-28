#include <QDebug>
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(Time, CheckRealTime)
  {
    Time &time = Time::GetInstance();
    time.UseRealTime();
    EXPECT_TRUE(time.UsingRealTime());
    time.UseRealTime();
    qint64 now0 = time.MSecsSinceEpoch();
    Sleeper::MSleep(1);
    qint64 now1 = time.MSecsSinceEpoch();
    EXPECT_LT(now0, now1);
  }

  TEST(Time, CheckVirtualTime)
  {
    Time &time = Time::GetInstance();
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
    Timer &timer = Timer::GetInstance();
    timer.UseRealTime();
    int sleep = 5;
    MockTimerCallback mtc = MockTimerCallback(2);
    TimerMethod<MockTimerCallback, int> *cb0 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    TimerEvent qc0 = timer.QueueCallback(cb0, sleep / 2, sleep * 3);
    MockExec();
    Sleeper::MSleep(sleep / 8);
    MockExec();
    EXPECT_EQ(2, mtc.value);
    Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    TimerMethod<MockTimerCallback, int> *cb1 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    TimerEvent qc1 = timer.QueueCallback(cb1, sleep / 2);
    Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(6, mtc.value);
    Sleeper::MSleep(sleep * 3);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    qc0.Stop();
    qc1.Stop();
  }

  TEST(Time, CheckTimerEventRealDecreasing)
  {
    Timer &timer = Timer::GetInstance();
    timer.UseRealTime();
    int sleep = 5;
    MockTimerCallback mtc = MockTimerCallback(2);
    TimerMethod<MockTimerCallback, int> *cb0 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    TimerMethod<MockTimerCallback, int> *cb1 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    TimerEvent qc0 = timer.QueueCallback(cb0, sleep / 2 + sleep);
    TimerEvent qc1 = timer.QueueCallback(cb1, sleep / 2);
    MockExec();
    Sleeper::MSleep(sleep / 8);
    MockExec();
    EXPECT_EQ(2, mtc.value);
    Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(5, mtc.value);
    Sleeper::MSleep(sleep);
    MockExec();
    EXPECT_EQ(6, mtc.value);
    qc0.Stop();
    qc1.Stop();
  }

  TEST(Time, CheckTimerEventVirtual)
  {
    Timer &timer = Timer::GetInstance();
    timer.UseVirtualTime();
    int sleep = 1000*1000;
    MockTimerCallback mtc = MockTimerCallback(2);
    TimerMethod<MockTimerCallback, int> *cb0 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 6);
    TimerMethod<MockTimerCallback, int> *cb1 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 7);
    TimerMethod<MockTimerCallback, int> *cb2 =
      new TimerMethod<MockTimerCallback, int>(&mtc, &MockTimerCallback::Set, 5);
    TimerEvent qc0 = timer.QueueCallback(cb0, sleep * 3);
    TimerEvent qc1 = timer.QueueCallback(cb1, sleep * 5);
    TimerEvent qc2 = timer.QueueCallback(cb2, sleep);

    Time &time = Time::GetInstance();
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

  TEST(Time, Verify_46_Hack)
  {
    qint64 MSecsPerDay = 86400000;
    QDateTime epoch = QDateTime::fromString("1970-01-01T00:00:00.000", Qt::ISODate);
    epoch.setTimeSpec(Qt::UTC);

    Time &time = Time::GetInstance();
    time.UseRealTime();

    QDateTime now = time.CurrentTime();
    QDateTime now_46 = QDateTime::currentDateTime().toUTC();

    EXPECT_EQ(now_46.date(), now.date());
    EXPECT_TRUE(qAbs(now_46.time().msecsTo(now.time())) < 100);

    qint64 msecs = time.MSecsSinceEpoch();
    now = QDateTime::currentDateTime().toUTC();
    int days_46 = epoch.date().daysTo(now.date());
    int msecs_46 = epoch.time().msecsTo(now.time());
    qint64 total_msecs_46 = (days_46 * MSecsPerDay) + msecs_46;

    EXPECT_TRUE(qAbs(msecs - total_msecs_46) < 100);

    time.UseVirtualTime();

    now = time.CurrentTime();
    now_46 = epoch.addMSecs(time.MSecsSinceEpoch());
    EXPECT_EQ(now, now_46);

    for(int i = 0; i < 50; i++) {
      time.IncrementVirtualClock(Random::GetInstance().GetInt());
      now = time.CurrentTime();
      now_46 = epoch.addMSecs(time.MSecsSinceEpoch());
      EXPECT_EQ(now, now_46);
    }
  }
}
}
