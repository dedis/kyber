#include "DissentTest.hpp"
#include <QDebug>

using namespace Dissent::Messaging;
using namespace Dissent::Transports;
using namespace Dissent::Utils;

namespace Dissent {
namespace Tests {
  TEST(BufferEdgeListener, Basic)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    BufferEdgeListener be0(addr0);
    MockEdgeHandler meh0(&be0);

    const BufferAddress addr1(10001);
    BufferEdgeListener be1(addr1);
    MockEdgeHandler meh1(&be1);

    EXPECT_TRUE(meh0.edge.isNull());
    EXPECT_TRUE(meh1.edge.isNull());

    be1.CreateEdgeTo(addr0);
    EXPECT_FALSE(meh0.edge.isNull());
    EXPECT_FALSE(meh1.edge.isNull());

    EXPECT_FALSE(meh1.edge->Incoming());
    EXPECT_TRUE(meh0.edge->Incoming());

    RpcHandler rpc0;
    meh0.edge->SetSink(&rpc0);

    TestRpc test0;
    rpc0.Register(new RpcMethod<TestRpc>(test0, &TestRpc::Add), "add");

    RpcHandler rpc1;
    meh1.edge->SetSink(&rpc1);

    TestRpcResponse test1;
    RpcMethod<TestRpcResponse> cb = RpcMethod<TestRpcResponse>(test1, &TestRpcResponse::HandleResponse);

    QVariantMap request;
    request["method"] = "add";
    request["x"] = 3;
    request["y"] = 6;

    EXPECT_EQ(-1, test1.value);
    rpc1.SendRequest(request, meh1.edge.data(), &cb);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(9, test1.value);
  }
}
}
