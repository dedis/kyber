#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Overlay;
    using namespace Dissent::Utils;
  }

  TEST(BasicGossip, Bootstrap)
  {
    int count = 40;
    Timer::GetInstance().UseVirtualTime();
    QVector<QSharedPointer<BasicGossip> > nodes;
    QList<Address> remote;
    QList<Address> local;
    BufferAddress ba = BufferAddress(1);
    local.append(ba);
    remote.append(ba);

    nodes.append(QSharedPointer<BasicGossip>(new BasicGossip(local, remote)));

    local[0] = AddressFactory::GetInstance().CreateAny("buffer");
    for(int idx = 1; idx < count; idx++) {
      nodes.append(QSharedPointer<BasicGossip>(new BasicGossip(local, remote)));
    }

    foreach(QSharedPointer<BasicGossip> bg, nodes) {
      bg->Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<BasicGossip> bg, nodes) {
      EXPECT_EQ(bg->GetConnectionTable().GetConnections().count(), count - 1);
    }

    foreach(QSharedPointer<BasicGossip> bg, nodes) {
      bg->Stop();
    }

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<BasicGossip> bg, nodes) {
      EXPECT_EQ(bg->GetConnectionTable().GetConnections().count(), 0);
    }
  }
}
}
