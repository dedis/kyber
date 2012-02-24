#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {
  TEST(Connection, SingleConnect)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    cm1.ConnectTo(addr0);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    TestRpc test0;
    QSharedPointer<RequestHandler> req_h(new RequestHandler(&test0, "Add"));
    rpc0->Register("Add", req_h);

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(
        new ResponseHandler(&test1, "HandleResponse"));

    ASSERT_EQ(0, test1.GetValue());
    
    QVariantList data;
    data.append(3);
    data.append(6);
    rpc1->SendRequest(cm1.GetConnectionTable().GetConnection(id0),
        "Add", data, res_h);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_EQ(9, test1.GetValue());

    cm1.GetConnectionTable().GetConnection(id0)->Disconnect();

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
  }

  TEST(Connection, SimultaneousConnect)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));

    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    TestRpc test0;
    rpc0->Register("Add", &test0, "Add");

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(
        new ResponseHandler(&test1, "HandleResponse"));

    QVariantList data;
    data.append(3);
    data.append(6);
    rpc1->SendRequest(cm1.GetConnectionTable().GetConnection(id0), "Add", data, res_h);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_EQ(9, test1.GetValue());

    cm1.GetConnectionTable().GetConnection(id0)->Disconnect();

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
  }

  TEST(Connection, SimultaneousDisconnect)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    TestRpc test0;
    rpc0->Register("Add", &test0, "Add");

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(
        new ResponseHandler(&test1, "HandleResponse"));

    QVariantList data;
    data.append(3);
    data.append(6);

    ASSERT_EQ(0, test1.GetValue());
    rpc1->SendRequest(cm1.GetConnectionTable().GetConnection(id0), "Add", data, res_h);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_EQ(9, test1.GetValue());

    cm1.GetConnectionTable().GetConnection(id0)->Disconnect();
    cm0.GetConnectionTable().GetConnection(id1)->Disconnect();

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
  }

  TEST(Connection, Disconnect)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    cm0.Stop();

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));

    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
  }

  TEST(Connection, Reconnect)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(1000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    cm1.GetConnectionTable().GetConnection(id0)->Disconnect();

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));

    cm1.ConnectTo(addr0);
    cm0.ConnectTo(addr1);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));
  }

  TEST(Connection, Relay)
  {
    Timer::GetInstance().UseVirtualTime();

    const BufferAddress addr0(10000);
    EdgeListener *be0 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0);
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(be0));
    be0->Start();

    RelayEdgeListener *rel0 = new RelayEdgeListener(id0, cm0.GetConnectionTable(), rpc0);
    cm0.AddEdgeListener(QSharedPointer<EdgeListener>(rel0));
    rel0->Start();

    const BufferAddress addr1(10001);
    EdgeListener *be1 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1);
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();

    RelayEdgeListener *rel1 = new RelayEdgeListener(id1, cm1.GetConnectionTable(), rpc1);
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(rel1));
    rel1->Start();

    const BufferAddress addr2(10002);
    EdgeListener *be2 = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr2);
    QSharedPointer<RpcHandler> rpc2(new RpcHandler());
    Id id2;
    ConnectionManager cm2(id2, rpc2);
    cm2.AddEdgeListener(QSharedPointer<EdgeListener>(be2));
    be2->Start();

    RelayEdgeListener *rel2 = new RelayEdgeListener(id2, cm2.GetConnectionTable(), rpc2);
    cm2.AddEdgeListener(QSharedPointer<EdgeListener>(rel2));
    rel2->Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id2));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id2));
    ASSERT_FALSE(cm2.GetConnectionTable().GetConnection(id0));
    ASSERT_FALSE(cm2.GetConnectionTable().GetConnection(id1));

    cm0.ConnectTo(addr1);
    cm1.ConnectTo(addr2);

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id2));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id2));
    ASSERT_FALSE(cm2.GetConnectionTable().GetConnection(id0));
    ASSERT_TRUE(cm2.GetConnectionTable().GetConnection(id1));

    rel0->CreateEdgeTo(id2);

    next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id2));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id2));
    ASSERT_TRUE(cm2.GetConnectionTable().GetConnection(id0));
    ASSERT_TRUE(cm2.GetConnectionTable().GetConnection(id1));
  }
}
}
