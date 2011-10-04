#include "ConnectionManager.hpp"

namespace Dissent {
namespace Connections {
  ConnectionManager::ConnectionManager(const Id &local_id, RpcHandler *rpc) :
    _inquire(RpcMethod<ConnectionManager>(*this, &ConnectionManager::Inquire)),
    _inquired(RpcMethod<ConnectionManager>(*this, &ConnectionManager::Inquired)),
    _close(RpcMethod<ConnectionManager>(*this, &ConnectionManager::Close)),
    _connect(RpcMethod<ConnectionManager>(*this, &ConnectionManager::Connect)),
    _disconnect(RpcMethod<ConnectionManager>(*this, &ConnectionManager::Disconnect)),
    _local_id(local_id), _rpc(rpc), _closed(false)
  {
    _rpc->Register(&_inquire, "CM::Inquire");
    _rpc->Register(&_close, "CM::Close");
    _rpc->Register(&_connect, "CM::Connect");
    _rpc->Register(&_disconnect, "CM::Disconnect");
  }

  ConnectionManager::~ConnectionManager()
  {
    _rpc->Unregister("CM::Inquire");
    _rpc->Unregister("CM::Close");
    _rpc->Unregister("CM::Connect");
    _rpc->Unregister("CM::Disconnect");
  }

  void ConnectionManager::AddEdgeListener(EdgeListener *el)
  {
    if(_closed) {
      qWarning() << "Attempting to add an EdgeListener after calling Disconnect.";
      return;
    }

    _el.reset(el);
    QObject::connect(el, SIGNAL(NewEdgeSignal(Edge *)),
        this, SLOT(HandleNewEdge(Edge *)));
  }

  void ConnectionManager::ConnectTo(const Address &addr)
  {
    if(_closed) {
      qWarning() << "Attempting to Connect to a remote node after calling Disconnect.";
      return;
    }

    _el->CreateEdgeTo(addr);
  }

  void ConnectionManager::Disconnect()
  {
    if(_closed) {
      qWarning() << "Called Disconnect twice on ConnectionManager.";
      return;
    }

    _closed = true;
    foreach(Connection *con, _con_tab.GetConnections()) {
      con->Disconnect();
    }
    _el->Stop();
  }

  void ConnectionManager::HandleNewEdge(Edge *edge)
  {
    edge->SetSink(_rpc);
    if(edge->Incoming()) {
      _rem_con_tab.AddEdge(edge);
      return;
    }

    _con_tab.AddEdge(edge);
    QVariantMap request;
    request["method"] = "CM::Inquire";
    request["peer_id"] = _local_id.GetByteArray();
    _rpc->SendRequest(request, edge, &_inquired);
  }

  void ConnectionManager::Inquire(RpcRequest &request)
  {
    QVariantMap response;
    response["peer_id"] = _local_id.GetByteArray();
    request.Respond(response);
  }

  void ConnectionManager::Inquired(RpcRequest &response)
  {
    ISender *from = response.GetFrom();
    Edge *edge = dynamic_cast<Edge *>(from);
    if(edge == 0) {
      qWarning() << "Received an inquired from a non-Edge: " << from->ToString();
      return;
    } else if(edge->Incoming()) {
      qWarning() << "We would never make an inquire call on an incoming edge: " << from->ToString();
      return;
    }

    QByteArray brem_id = response.GetMessage()["peer_id"].toByteArray();

    if(brem_id.isEmpty()) {
      qWarning() << "Invalid ConnectionEstablished, no id";
      return;
    }

    Id rem_id(brem_id);
    if(_con_tab.GetConnection(rem_id) != 0) {
      qWarning() << "Already have a connection to: " << rem_id.ToString() << 
        " closing Edge: " << edge->ToString();
      QVariantMap notification;
      notification["method"] = "CM::Close";
      _rpc->SendNotification(notification, edge);
      edge->DelayedClose("Duplicate connection");
      return;
    }

    QVariantMap notification;
    notification["method"] = "CM::Connect";
    notification["peer_id"] = _local_id.GetByteArray();
    _rpc->SendNotification(notification, edge);

    qDebug() << _local_id.ToString() << ": Creating new connection to " << rem_id.ToString();
    Connection *con = new Connection(edge, _local_id, rem_id);
    _con_tab.AddConnection(con);

    QObject::connect(con, SIGNAL(CalledDisconnect(Connection *)),
        this, SLOT(HandleDisconnect(Connection *)));
    QObject::connect(con, SIGNAL(Disconnected(Connection *, const QString &)),
        this, SLOT(HandleDisconnected(Connection *, const QString &)));
    emit NewConnectionSignal(con);
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
    if(old_con != 0) {
    }

    Connection *con = new Connection(edge, _local_id, rem_id);
    _rem_con_tab.AddConnection(con);
    qDebug() << _local_id.ToString() << ": Handle new connection from " << rem_id.ToString();
    QObject::connect(con, SIGNAL(Disconnected(Connection *, const QString &)),
        this, SLOT(HandleDisconnected(Connection *, const QString &)));
  }

  void ConnectionManager::Close(RpcRequest &notification)
  {
    Edge *edge = dynamic_cast<Edge *>(notification.GetFrom());
    if(edge == 0) {
      qWarning() << "Connection attempt Edge close not from an Edge: " << notification.GetFrom()->ToString();
      return;
    }

    Connection *con = _rem_con_tab.GetConnection(edge);
    if(con != 0) {
    }

    edge->Close("Closed from remote peer");
    delete edge;
  }

  void ConnectionManager::HandleDisconnect(Connection *con)
  {
    _con_tab.Disconnect(con);

    QVariantMap notification;
    notification["method"] = "CM::Disconnect";
    _rpc->SendNotification(notification, con);

    qDebug() << "Handle disconnect on: " << con->ToString();
    con->GetEdge()->DelayedClose("Local disconnect request");
  }

  void ConnectionManager::HandleDisconnected(Connection *con, const QString &reason)
  {
    qDebug() << "Edge disconnected now removing Connection: " << con->ToString()
      << ", because: " << reason;
    if(con->GetEdge()->Incoming()) {
     _rem_con_tab.RemoveConnection(con);
    } else {
     _con_tab.RemoveConnection(con);
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
    if(!_rem_con_tab.Disconnect(con)) {
      qWarning() << "No connection information stored locally.";
    }
    con->GetEdge()->Close("Remote disconnect");
  }

  void ConnectionManager::HandleEdgeClose(const Edge *edge, const QString &)
  {
    ConnectionTable &con_tab = edge->Incoming() ? _rem_con_tab : _con_tab;
    if(!con_tab.RemoveEdge(edge)) {
    }
  }
}
}
