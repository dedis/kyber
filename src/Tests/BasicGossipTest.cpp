#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Utils;
  }

  BasicGossip *GenerateNode(int local_idx, QList<Address> remote)
  {
    QList<Address> local;
    local.append(BufferAddress(local_idx));
    return new BasicGossip(local, remote);
  }

  TEST(BasicGossip, Bootstrap)
  {
    int count = 40;
    Timer::GetInstance().UseVirtualTime();
    QVector<QSharedPointer<BasicGossip> > nodes;
    QList<Address> remote;

    nodes.append(QSharedPointer<BasicGossip>(GenerateNode(1, remote)));

    remote.append(BufferAddress(1));
    for(int idx = 1; idx < 40; idx++) {
      nodes.append(QSharedPointer<BasicGossip>(GenerateNode(idx + 1, remote)));
    }

    foreach(QSharedPointer<BasicGossip> sn, nodes) {
      sn->Start();
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    foreach(QSharedPointer<BasicGossip> sn, nodes) {
      EXPECT_EQ(sn->GetConnectionTable().GetConnections().count(), count - 1);
    }
  }
}
}
