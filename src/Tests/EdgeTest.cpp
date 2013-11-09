#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {
  TEST(EdgeTest, BufferBasic)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    BufferEdgeListener be0(addr0);
    MockEdgeHandler meh0(&be0);
    be0.Start();

    const BufferAddress addr1(10001);
    BufferEdgeListener be1(addr1);
    MockEdgeHandler meh1(&be1);
    be1.Start();

    EXPECT_TRUE(meh0.edge.isNull());
    EXPECT_TRUE(meh1.edge.isNull());

    be1.CreateEdgeTo(addr0);
    RunUntil();

    EXPECT_FALSE(meh0.edge.isNull());
    EXPECT_FALSE(meh1.edge.isNull());

    EXPECT_TRUE(meh1.edge->Outbound());
    EXPECT_FALSE(meh0.edge->Outbound());

    RpcHandler rpc0;
    meh0.edge->SetSink(&rpc0);

    TestRpc test0;
    QSharedPointer<RequestHandler> req_h(new RequestHandler(&test0, "Add"));
    rpc0.Register("add", req_h);

    RpcHandler rpc1;
    meh1.edge->SetSink(&rpc1);

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(
        new ResponseHandler(&test1, "HandleResponse"));

    QVariantList data;
    data.append(3);
    data.append(6);

    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    rpc1.SendRequest(meh1.edge, "add", data, res_h);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    EXPECT_EQ(9, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());
  }

  TEST(EdgeTest, BufferFail)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr(10001);
    BufferEdgeListener be(addr);
    be.Start();
    MockEdgeHandler meh(&be);
    SignalCounter sc;
    QObject::connect(&be,
        SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        &sc,
        SLOT(Counter()));

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
    te.Start();
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
