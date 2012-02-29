#include "OverlayHelper.hpp"

namespace Dissent {
namespace Tests {
  void SendTest(const QList<QSharedPointer<Node> > &nodes, bool live)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[0]->GetSessionManager().GetDefaultSession()->Send(msg);

    SignalCounter sc(live ? nodes.count() : -1);
    foreach(QSharedPointer<Node> node, nodes) {
      QSharedPointer<BufferSink> sink = node->GetSink().dynamicCast<BufferSink>();
      if(!sink) {
        qFatal("BufferSink expected");
      }
      QObject::connect(sink.data(), SIGNAL(DataReceived()), &sc, SLOT(Counter()));
    }

    if(live) {
      MockExecLoop(sc);
    } else {
      int count = nodes.count();
      qint64 next = Timer::GetInstance().VirtualRun();
      while(next != -1 && sc.GetCount() != count) {
        Time::GetInstance().IncrementVirtualClock(next);
        next = Timer::GetInstance().VirtualRun();
      }
    }

    foreach(QSharedPointer<Node> node, nodes) {
      QSharedPointer<BufferSink> sink = node->GetSink().dynamicCast<BufferSink>();
      if(!sink) {
        qFatal("BufferSink expected");
      }
      EXPECT_EQ(msg, sink->Last().second);
    }
  }

  void TerminateOverlay(const QList<QSharedPointer<Node> > &nodes, bool live)
  {
    SignalCounter sc(live ? nodes.count() : -1);
    foreach(const QSharedPointer<Node> &node, nodes) {
      QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnected()),
          &sc, SLOT(Counter()));
      node->GetOverlay()->Stop();
    }

    if(live) {
      MockExecLoop(sc);
    } else {
      qint64 next = Timer::GetInstance().VirtualRun();
      while(next != -1 && sc.GetCount() != nodes.count()) {
        Time::GetInstance().IncrementVirtualClock(next);
        next = Timer::GetInstance().VirtualRun();
      }
    }

    EXPECT_EQ(sc.GetCount(), nodes.count());

    foreach(const QSharedPointer<Node> &node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionTable().GetConnections().count(), 0);
    }
  }
}
}
