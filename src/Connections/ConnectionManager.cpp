#include "../Messaging/RpcHandler.hpp"

#include "Connection.hpp"
#include "ConnectionManager.hpp"

namespace Dissent {
namespace Connections {
  ConnectionManager::ConnectionManager(const Id &local_id, RpcHandler &rpc) :
    _inquire(this, &ConnectionManager::Inquire),
    _inquired(this, &ConnectionManager::Inquired),
    _close(this, &ConnectionManager::Close),
    _connect(this, &ConnectionManager::Connect),
    _disconnect(this, &ConnectionManager::Disconnect),
    _con_tab(local_id), _local_id(local_id), _rpc(rpc), _closed(false)
  {
    _rpc.Register(&_inquire, "CM::Inquire");
    _rpc.Register(&_close, "CM::Close");
    _rpc.Register(&_connect, "CM::Connect");
    _rpc.Register(&_disconnect, "CM::Disconnect");

    Connection *con = _con_tab.GetConnection(_local_id);
    con->SetSink(&_rpc);
    QObject::connect(con->GetEdge().data(), SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));
    QObject::connect(con, SIGNAL(CalledDisconnect()), this, SLOT(HandleDisconnect()));
    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));
  }

  ConnectionManager::~ConnectionManager()
  {
    _rpc.Unregister("CM::Inquire");
    _rpc.Unregister("CM::Close");
    _rpc.Unregister("CM::Connect");
    _rpc.Unregister("CM::Disconnect");
  }

  void ConnectionManager::AddEdgeListener(QSharedPointer<EdgeListener> el)
  {
    if(_closed) {
      qWarning() << "Attempting to add an EdgeListener after calling Disconnect.";
      return;
    }

    _edge_factory.AddEdgeListener(el);
    QObject::connect(el.data(), SIGNAL(NewEdge(Edge *)),
        this, SLOT(HandleNewEdge(Edge *)));
    QObject::connect(el.data(), SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        this, SLOT(HandleEdgeCreationFailure(const Address &, const QString&)));
  }

  void ConnectionManager::ConnectTo(const Address &addr)
  {
    if(_closed) {
      qWarning() << "Attempting to Connect to a remote node after calling Disconnect.";
      return;
    }

    if(!_edge_factory.CreateEdgeTo(addr)) {
      emit ConnectionAttemptFailure(addr,
          "No EdgeListener to handle request");
    }
  }

  void ConnectionManager::Disconnect()
  {
    if(_closed) {
      qWarning() << "Called Disconnect twice on ConnectionManager.";
      return;
    }

    _closed = true;

    bool emit_dis = (_con_tab.GetEdges().count() == 0)
      && (_rem_con_tab.GetEdges().count() == 0);

    foreach(Connection *con, _con_tab.GetConnections()) {
      con->Disconnect();
    }

    foreach(Connection *con, _rem_con_tab.GetConnections()) {
      con->Disconnect();
    }

    foreach(QSharedPointer<Edge> edge, _con_tab.GetEdges()) {
      if(!edge->IsClosed()) {
        edge->Close("Disconnecting");
      }
    }
    
    foreach(QSharedPointer<Edge> edge, _rem_con_tab.GetEdges()) {
      if(!edge->IsClosed()) {
        edge->Close("Disconnecting");
      }
    }

    _edge_factory.Stop();

    if(emit_dis) {
      emit Disconnected();
    } 
  }

  void ConnectionManager::HandleNewEdge(Edge *edge)
  {
    edge->SetSink(&_rpc);

    QObject::connect(edge, SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));

    if(!edge->Outbound()) {
      _rem_con_tab.AddEdge(edge);
      return;
    }

    _con_tab.AddEdge(edge);
    QVariantMap request;
    request["method"] = "CM::Inquire";
    request["peer_id"] = _local_id.GetByteArray();
    _rpc.SendRequest(request, edge, &_inquired);
  }

  void ConnectionManager::HandleEdgeCreationFailure(const Address &to,
      const QString &reason)
  {
    emit ConnectionAttemptFailure(to, reason);
  }

  void ConnectionManager::Inquire(RpcRequest &request)
  {
    QVariantMap response;
    response["peer_id"] = _local_id.GetByteArray();
    request.Respond(response);
  }

  void ConnectionManager::Inquired(RpcRequest &response)
  {
    Dissent::Messaging::ISender *from = response.GetFrom();
    Edge *edge = dynamic_cast<Edge *>(from);
    if(edge == 0) {
      qWarning() << "Received an inquired from a non-Edge: " << from->ToString();
      return;
    } else if(!edge->Outbound()) {
      qWarning() << "We would never make an inquire call on an incoming edge: " << from->ToString();
      return;
    }

    QByteArray brem_id = response.GetMessage()["peer_id"].toByteArray();

    if(brem_id.isEmpty()) {
      qWarning() << "Invalid ConnectionEstablished, no id";
      return;
    }

    Id rem_id(brem_id);

    if(rem_id == _local_id) {
      qDebug() << "Attempting to connect to ourself";
      QVariantMap notification;
      notification["method"] = "CM::Close";
      _rpc.SendNotification(notification, edge);
      edge->Close("Attempting to connect to ourself");
      emit ConnectionAttemptFailure(edge->GetRemoteAddress(),
          "Attempting to connect to ourself");
      return;
    }

    if(_con_tab.GetConnection(rem_id) != 0) {
      qWarning() << "Already have a connection to: " << rem_id.ToString() << 
        " closing Edge: " << edge->ToString();
      QVariantMap notification;
      notification["method"] = "CM::Close";
      _rpc.SendNotification(notification, edge);
      edge->Close("Duplicate connection");
      emit ConnectionAttemptFailure(edge->GetRemoteAddress(),
          "Duplicate connection");
      return;
    }

    QSharedPointer<Edge> pedge = _con_tab.GetEdge(edge);
    if(pedge.isNull()) {
      qCritical() << "An edge attempted to create a connection, but there "
       "is no record of it" << edge->ToString();
      return;
    }

    QVariantMap notification;
    notification["method"] = "CM::Connect";
    notification["peer_id"] = _local_id.GetByteArray();
    _rpc.SendNotification(notification, edge);

    qDebug() << _local_id.ToString() << ": Creating new connection to " << rem_id.ToString();
    Connection *con = new Connection(pedge, _local_id, rem_id);
    _con_tab.AddConnection(con);

    QObject::connect(con, SIGNAL(CalledDisconnect()), this, SLOT(HandleDisconnect()));
    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));
    emit NewConnection(con, true);
  }

  void ConnectionManager::Connect(RpcRequest &notification)
  {
    Edge *edge = dynamic_cast<Edge *>(notification.GetFrom());
    if(edge == 0) {
      qWarning() << "Connection attempt not from an Edge: " << notification.GetFrom()->ToString();
      return;
    }
    
    QByteArray brem_id = notification.GetMessage()["peer_id"].toByteArray();

    if(brem_id.isEmpty()) {
      qWarning() << "Invalid ConnectionEstablished, no id";
      return;
    }

    Id rem_id(brem_id);
    Connection *old_con = _rem_con_tab.GetConnection(rem_id);
    // XXX if there is an old connection and the node doesn't want it, we need
    // to close it
    if(old_con != 0) {
      qDebug() << "Disconnecting old connection";
      old_con->Disconnect();
    }

    QSharedPointer<Edge> pedge = _rem_con_tab.GetEdge(edge);
    if(pedge.isNull()) {
      qCritical() << "An edge attempted to create a connection, but there "
       "is no record of it" << edge->ToString();
      return;
    }

    Connection *con = new Connection(pedge, _local_id, rem_id);
    _rem_con_tab.AddConnection(con);
    qDebug() << _local_id.ToString() << ": Handle new connection from " << rem_id.ToString();
    QObject::connect(con, SIGNAL(CalledDisconnect()), this, SLOT(HandleDisconnect()));
    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));
    emit NewConnection(con, false);
  }

  void ConnectionManager::Close(RpcRequest &notification)
  {
    Edge *edge = dynamic_cast<Edge *>(notification.GetFrom());
    if(edge == 0) {
      qWarning() << "Connection attempt Edge close not from an Edge: " << notification.GetFrom()->ToString();
      return;
    }

    edge->Close("Closed from remote peer");
  }

  void ConnectionManager::HandleDisconnect()
  {
    Connection *con = qobject_cast<Connection *>(sender());
    if(_con_tab.Contains(con)) {
      _con_tab.Disconnect(con);
    } else {
      _rem_con_tab.Disconnect(con);
    }

    if(con->GetRemoteId() != _local_id) {
      QVariantMap notification;
      notification["method"] = "CM::Disconnect";
      _rpc.SendNotification(notification, con);
    }

    qDebug() << "Handle disconnect on: " << con->ToString();
    con->GetEdge()->Close("Local disconnect request");
  }

  void ConnectionManager::HandleDisconnected(const QString &reason)
  {
    Connection *con = qobject_cast<Connection *>(sender());
    qDebug() << "Edge disconnected now removing Connection: " << con->ToString()
      << ", because: " << reason;
    if(con->GetEdge()->Outbound()) {
     _con_tab.RemoveConnection(con);
    } else {
     _rem_con_tab.RemoveConnection(con);
    }
  }

  void ConnectionManager::Disconnect(RpcRequest &notification)
  {
    Connection *con = dynamic_cast<Connection *>(notification.GetFrom());
    if(con == 0) {
      qWarning() << "Received DisconnectResponse from a non-connection: " << notification.GetFrom()->ToString();
      return;
    }

    qDebug() << "Received disconnect for: " << con->ToString();
    if(_rem_con_tab.Contains(con)) {
      _rem_con_tab.Disconnect(con);
    } else {
      _con_tab.Disconnect(con);
    }
    con->GetEdge()->Close("Remote disconnect");
  }

  void ConnectionManager::HandleEdgeClose(const QString &)
  {
    Edge *edge = qobject_cast<Edge *>(sender());
    qDebug() << "Edge closed: " << edge->ToString();
    ConnectionTable &con_tab = edge->Outbound() ? _con_tab : _rem_con_tab;
    if(!con_tab.RemoveEdge(edge)) {
      qWarning() << "Edge closed but no Edge found in CT:" << edge->ToString();
    }

    if(!_closed) {
      return;
    }

    if(_con_tab.GetEdges().count() == 0 && _rem_con_tab.GetEdges().count() == 0) {
      emit Disconnected();
    }
  }
}
}
