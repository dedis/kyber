#include "Connection.hpp"
#include "Transports/Edge.hpp"

namespace Dissent {
namespace Connections {
  Connection::Connection(const QSharedPointer<Edge> &edge, const Id &local_id,
      const Id &remote_id) :
    _edge(edge),
    _local_id(local_id),
    _remote_id(remote_id)
  {
    ISink *sink = _edge->SetSink(this);
    SetSink(sink);
    QObject::connect(_edge.data(), SIGNAL(StoppedSignal()),
        this, SLOT(HandleEdgeClose()));
  }

  QString Connection::ToString() const
  {
    return QString("Connection, Local: " + _local_id.ToString() +
        (_edge->Outbound() ? " => " : " <= ") + ", Remote: " +
        _remote_id.ToString() + ", Edge: " + _edge->ToString());
  }

  void Connection::Disconnect()
  {
    qDebug() << "Called disconnect on: " << this->ToString();
    emit CalledDisconnect();
  }

  void Connection::Send(const QByteArray &data)
  {
    _edge->Send(data);
  }

  void Connection::HandleEdgeClose()
  {
    Edge *edge = qobject_cast<Edge *>(sender());
    if(edge == _edge.data()) {
      emit Disconnected(edge->GetStoppedReason());
    }
  }
}
}
