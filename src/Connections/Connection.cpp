#include "Connection.hpp"
#include "Transports/Edge.hpp"

namespace Dissent {
namespace Connections {
  Connection::Connection(QSharedPointer<Edge> edge, const Id &local_id,
      const Id &remote_id) :
    _edge(edge), _local_id(local_id), _remote_id(remote_id)
  {
    ISink *old_sink = _edge->SetSink(this);
    SetSink(old_sink);
    QObject::connect(edge.data(), SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));
  }

  QString Connection::ToString() const
  {
    return QString("Connection, Local: " + _local_id.ToString() +
        (_edge->Outbound() ? " => " : " <= ") + ", Remote: " +
        _remote_id.ToString() + ", Edge: " + _edge->ToString());
  }

  void Connection::Disconnect()
  {
    SetSink(0);
    qDebug() << "Called disconnect on: " << this->ToString();
    emit CalledDisconnect();
  }

  void Connection::Send(const QByteArray &data)
  {
    _edge->Send(data);
  }

  void Connection::HandleEdgeClose(const QString &reason)
  {
    Edge *edge = qobject_cast<Edge *>(sender());
    if(edge == _edge.data()) {
      emit Disconnected(reason);
      delete this;
    }
  }
}
}
