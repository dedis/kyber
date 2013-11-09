#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {
  TEST(Connection, SingleConnect)
  {
    ConnectionManager::UseTimer = false;
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
    ConnectionManager::UseTimer = true;
  }

  TEST(Connection, SimultaneousConnect)
  {
    ConnectionManager::UseTimer = false;
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
    ConnectionManager::UseTimer = true;
  }

  TEST(Connection, SimultaneousDisconnect)
  {
    ConnectionManager::UseTimer = false;
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
    ConnectionManager::UseTimer = true;
  }

  TEST(Connection, Disconnect)
  {
    ConnectionManager::UseTimer = false;
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
    ConnectionManager::UseTimer = true;
  }

  TEST(Connection, Reconnect)
  {
    ConnectionManager::UseTimer = false;
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
    ConnectionManager::UseTimer = true;
  }

  TEST(Connection, Timeout)
  {
    Timer::GetInstance().UseVirtualTime();

    SignalCounter sc_new;
    SignalCounter sc_close;

    const BufferAddress addr0(1000);
    QSharedPointer<EdgeListener> be0(EdgeListenerFactory::GetInstance().CreateEdgeListener(addr0));
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    Id id0;
    ConnectionManager cm0(id0, rpc0);
    QObject::connect(&cm0, SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        &sc_new, SLOT(Counter()));
    cm0.AddEdgeListener(be0);
    be0->Start();
    cm0.Start();

    const BufferAddress addr1(10001);
    QSharedPointer<EdgeListener> be1(EdgeListenerFactory::GetInstance().CreateEdgeListener(addr1));
    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    Id id1;
    ConnectionManager cm1(id1, rpc1);
    QObject::connect(&cm1, SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        &sc_new, SLOT(Counter()));
    cm1.AddEdgeListener(QSharedPointer<EdgeListener>(be1));
    be1->Start();
    cm1.Start();

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));
    cm1.ConnectTo(addr0);

    RunUntil(sc_new, 2);

    ASSERT_TRUE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    QObject::connect(cm0.GetConnectionTable().GetConnection(id1)->GetEdge().data(),
        SIGNAL(StoppedSignal()), &sc_close, SLOT(Counter()));
    QObject::connect(cm1.GetConnectionTable().GetConnection(id0)->GetEdge().data(),
        SIGNAL(StoppedSignal()), &sc_close, SLOT(Counter()));

    cm0.GetConnectionTable().GetConnection(id1)->GetEdge()->Stop("For fun");

    RunUntil(sc_close, 1);

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_TRUE(cm1.GetConnectionTable().GetConnection(id0));

    RunUntil(sc_close, 2);

    ASSERT_FALSE(cm0.GetConnectionTable().GetConnection(id1));
    ASSERT_FALSE(cm1.GetConnectionTable().GetConnection(id0));

    cm1.Stop();
    cm0.Stop();

    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }
  }
}
}
