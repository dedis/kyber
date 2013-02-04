#include "OverlayHelper.hpp"

namespace Dissent {
namespace Tests {
  void SendTest(const QList<QSharedPointer<Node> > &nodes, bool live)
  {
    QByteArray msg(512, 0);
    CryptoRandom().GenerateBlock(msg);
    nodes[0]->GetSessionManager().GetDefaultSession()->Send(msg);

    SignalCounter sc(live ? nodes.count() : -1);
    foreach(QSharedPointer<Node> node, nodes) {
      QSharedPointer<BufferSink> sink = node->GetSink().dynamicCast<BufferSink>();
      if(!sink) {
        qFatal("BufferSink expected");
      }
      QObject::connect(sink.data(), SIGNAL(DataReceived()), &sc, SLOT(Counter()));
    }

    qDebug() << "Sending data";

    if(live) {
      MockExecLoop(sc);
    } else {
      RunUntil(sc, nodes.count());
    }

    qDebug() << "Data received";

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

    qDebug() << "Stopping nodes";

    if(live) {
      MockExecLoop(sc);
    } else {
      RunUntil(sc, nodes.count());
    }

    qDebug() << "Nodes stopped";

    EXPECT_EQ(sc.GetCount(), nodes.count());

    foreach(const QSharedPointer<Node> &node, nodes) {
      EXPECT_EQ(node->GetOverlay()->GetConnectionTable().GetConnections().count(), 0);
    }
  }
}
}
