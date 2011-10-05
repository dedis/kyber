#include "Connection.hpp"

namespace Dissent {
namespace Connections {
  Connection::Connection(Edge *edge, const Id &local_id, const Id &remote_id) :
    _edge(edge), _local_id(local_id), _remote_id(remote_id)
  {
    ISink *old_sink = _edge->SetSink(this);
    SetSink(old_sink);
    QObject::connect(edge, SIGNAL(Closed(const Edge *, const QString &)),
        this, SLOT(HandleEdgeClose(const Edge *, const QString &)));
  }

  QString Connection::ToString() const
  {
    return QString("Connection, Local: " + _local_id.ToString() +
        (_edge->Outbound() ? " => " : " <= ") + ", Remote: " +
        _remote_id.ToString());
  }

  void Connection::Disconnect()
  {
    SetSink(0);
    qDebug() << "Called disconnect on: " << this->ToString();
    emit CalledDisconnect(this);
  }

  void Connection::Send(const QByteArray &data)
  {
    _edge->Send(data);
  }

  void Connection::HandleEdgeClose(const Edge *edge, const QString &reason)
  {
    if(edge == _edge.data()) {
      emit Disconnected(this, reason);
      delete this;
    }
  }
}
}
