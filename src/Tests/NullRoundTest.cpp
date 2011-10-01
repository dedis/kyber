#include "DissentTest.hpp"

using namespace Dissent::Utils;
using namespace Dissent::Messaging;
using namespace Dissent::Transports;
using namespace Dissent::Connections;
using namespace Dissent::Anonymity;

namespace Dissent {
namespace Tests {
  class NullTestNode {
    public:
      NullTestNode(int idx) : cm(Id(), &rpc), sm(&rpc)
      {
        BufferEdgeListener *be = new BufferEdgeListener(BufferAddress(idx));
        cm.AddEdgeListener(be);
        sm.SetSink(&sink);
      }

      ~NullTestNode()
      {
        if(round) {
          delete round;
        }
      }

      MockSink sink;
      RpcHandler rpc;
      ConnectionManager cm;
      SessionManager sm;
      Round *round;
  };

  TEST(NullRound, Basic)
  {
    int count = 40;
    Timer::GetInstance().UseVirtualTime();
    NullTestNode **nodes = new NullTestNode*[count];
    QVector<Id> group_vector;
    for(int idx = 0; idx < count; idx++) {
      nodes[idx] = new NullTestNode(idx+1);
      group_vector.append(nodes[idx]->cm.GetId());
    }

    Group group(group_vector);
    Id round_id;
    Id data;
    QByteArray msg = data.GetByteArray();
    for(int idx = 0; idx < count; idx++) {
      if(idx == 2) {
        nodes[idx]->round = new NullRound(nodes[idx]->cm.GetId(), group,
            nodes[idx]->cm.GetConnectionTable(), &(nodes[idx]->rpc),
            round_id, msg);
      } else {
        nodes[idx]->round = new NullRound(nodes[idx]->cm.GetId(), group,
            nodes[idx]->cm.GetConnectionTable(), &(nodes[idx]->rpc),
            round_id);
      }
      nodes[idx]->sm.AddRound(nodes[idx]->round);
    }

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        nodes[idx]->cm.ConnectTo(BufferAddress(jdx+1));
      }
    }

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.GetLastData().isEmpty());
    }

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->round->Start();
    }

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.GetLastData());
    }

    delete[] nodes;
  }
}
}
