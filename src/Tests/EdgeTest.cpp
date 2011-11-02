#include "DissentTest.hpp"
#include <QDebug>

using namespace Dissent::Messaging;
using namespace Dissent::Transports;
using namespace Dissent::Utils;

namespace Dissent {
namespace Tests {
  TEST(EdgeTest, BufferBasic)
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

    EXPECT_TRUE(meh1.edge->Outbound());
    EXPECT_FALSE(meh0.edge->Outbound());

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

  TEST(EdgeTest, BufferFail)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr(10001);
    BufferEdgeListener be(addr);
    MockEdgeHandler meh(&be);
    SignalCounter sc;
    QObject::connect(&be, SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        &sc, SLOT(Counter()));


    BufferAddress any;
    be.CreateEdgeTo(any);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != 1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), 1);
    sc.Reset();

    BufferAddress other_addr(1111);
    be.CreateEdgeTo(other_addr);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != 1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), 1);
    sc.Reset();

    BufferAddress bad_addr(QUrl("buffer://ha!"));
    be.CreateEdgeTo(bad_addr);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() != 1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(sc.GetCount(), 1);
  }

  TEST(EdgeTest, TcpFail)
  {
    Timer::GetInstance().UseRealTime();

    const TcpAddress addr("127.0.0.1", 33347);
    TcpEdgeListener te(addr);
    MockEdgeHandler meh(&te);
    SignalCounter sc(1);
    QObject::connect(&te, SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        &sc, SLOT(Counter()));

    TcpAddress any;
    te.CreateEdgeTo(any);
    MockExecLoop(sc);
    EXPECT_EQ(sc.GetCount(), 1);
    sc.Reset();

    TcpAddress other_addr("255.255.255.255.", 1111);
    te.CreateEdgeTo(other_addr);
    MockExecLoop(sc);
    EXPECT_EQ(sc.GetCount(), 1);
    sc.Reset();

    TcpAddress bad_addr(QUrl("tcp://ha!"));
    te.CreateEdgeTo(bad_addr);
    MockExecLoop(sc);
    EXPECT_EQ(sc.GetCount(), 1);
    sc.Reset();

    TcpAddress another_addr("5.5.5.5", 12345);
    te.CreateEdgeTo(another_addr);
    MockExecLoop(sc);
    EXPECT_EQ(sc.GetCount(), 1);
  }
}
}
