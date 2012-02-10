#include "Messaging/RpcHandler.hpp"
#include "Transports/AddressFactory.hpp"

#include "Connection.hpp"
#include "ConnectionManager.hpp"

using Dissent::Transports::AddressFactory;

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
    QObject::connect(el.data(), SIGNAL(NewEdge(QSharedPointer<Edge>)),
        this, SLOT(HandleNewEdge(QSharedPointer<Edge>)));
    QObject::connect(el.data(), SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        this, SLOT(HandleEdgeCreationFailure(const Address &, const QString&)));
  }

  void ConnectionManager::ConnectTo(const Address &addr)
  {
    if(_closed) {
      qWarning() << "Attempting to connect to a remote node after calling Disconnect.";
      return;
    }

    if(_active_addrs.contains(addr)) {
      qDebug() << "Attempting to connect multiple times to the same address:"
        << addr.ToString();
      return;
    }

    _active_addrs[addr] = true;
    _outstanding_con_attempts[addr] = true;
    if(!_edge_factory.CreateEdgeTo(addr)) {
      _outstanding_con_attempts.remove(addr);
      _active_addrs.remove(addr);
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

    bool emit_dis = (_con_tab.GetEdges().count() == 0);

    foreach(Connection *con, _con_tab.GetConnections()) {
      con->Disconnect();
    }

    foreach(QSharedPointer<Edge> edge, _con_tab.GetEdges()) {
      if(!edge->IsClosed()) {
        edge->Close("Disconnecting");
      }
    }
    
    _edge_factory.Stop();

    if(emit_dis) {
      emit Disconnected();
    } 
  }

  void ConnectionManager::HandleNewEdge(QSharedPointer<Edge> edge)
  {
    _con_tab.AddEdge(edge);
    edge->SetSink(&_rpc);

    QObject::connect(edge.data(), SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));

    if(!edge->Outbound()) {
      return;
    }

    _outstanding_con_attempts.remove(edge->GetRemoteAddress());
    if(!_active_addrs.contains(edge->GetRemoteAddress())) {
      qDebug() << "No record of attempting connection to" <<
        edge->GetRemoteAddress().ToString();
    }

    QVariantMap request;
    request["method"] = "CM::Inquire";
    request["peer_id"] = _local_id.GetByteArray();

    QString type = edge->GetLocalAddress().GetType();
    QSharedPointer<EdgeListener> el = _edge_factory.GetEdgeListener(type);
    request["persistent"] = el->GetAddress().ToString();

    _rpc.SendRequest(request, edge.data(), &_inquired);
  }

  void ConnectionManager::HandleEdgeCreationFailure(const Address &to,
      const QString &reason)
  {
    _active_addrs.remove(to);
    _outstanding_con_attempts.remove(to);
    emit ConnectionAttemptFailure(to, reason);
  }

  void ConnectionManager::Inquire(RpcRequest &request)
  {
    Dissent::Messaging::ISender *from = request.GetFrom();
    Edge *edge = dynamic_cast<Edge *>(from);
    if(edge == 0) {
      qWarning() << "Received an inquired from a non-Edge: " << from->ToString();
      return;
    } else if(edge->Outbound()) {
      qWarning() << "We should never receive an inquire call on an outbound edge: " << from->ToString();
      return;
    }

    QByteArray brem_id = request.GetMessage()["peer_id"].toByteArray();

    if(brem_id.isEmpty()) {
      qWarning() << "Invalid Inqiure, no id";
      return;
    }

    Id rem_id(brem_id);

    QVariantMap response;
    response["peer_id"] = _local_id.GetByteArray();
    request.Respond(response);

    QString saddr = request.GetMessage()["persistent"].toString();
    Address addr = AddressFactory::GetInstance().CreateAddress(saddr);
    edge->SetRemotePersistentAddress(addr);

    if(_local_id < rem_id) {
      BindEdge(edge, rem_id);
    } else if(_local_id == rem_id) {
      edge->Close("Attempting to connect to ourself");
    }
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


    if(_local_id < rem_id) {
      BindEdge(edge, rem_id);
    } else if(rem_id == _local_id) {
      Address addr = edge->GetRemoteAddress();
      qDebug() << "Attempting to connect to ourself";
      edge->Close("Attempting to connect to ourself");
      emit ConnectionAttemptFailure(addr, "Attempting to connect to ourself");
      return;
    }
  }

  void ConnectionManager::BindEdge(Edge *edge, const Id &rem_id)
  {
    /// @TODO add an extra variable to the connection message such as a session
    ///token so that quick reconnects can be enabled.
    if(_con_tab.GetConnection(rem_id) != 0) {
      qDebug() << "Already have a connection to: " << rem_id.ToString() << 
        " closing Edge: " << edge->ToString();
      QVariantMap notification;
      notification["method"] = "CM::Close";
      _rpc.SendNotification(notification, edge);
      Address addr = edge->GetRemoteAddress();
      edge->Close("Duplicate connection");
      emit ConnectionAttemptFailure(addr, "Duplicate connection");
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

    CreateConnection(pedge, rem_id);
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
    if(_local_id < rem_id) {
      qWarning() << "We should be sending CM::Connect, not the remote side.";
      return;
    }

    Connection *old_con = _con_tab.GetConnection(rem_id);
    // XXX if there is an old connection and the node doesn't want it, we need
    // to close it
    if(old_con != 0) {
      qDebug() << "Disconnecting old connection";
      old_con->Disconnect();
    }

    QSharedPointer<Edge> pedge = _con_tab.GetEdge(edge);
    if(pedge.isNull()) {
      qCritical() << "An edge attempted to create a connection, but there "
       "is no record of it" << edge->ToString();
      return;
    }

    CreateConnection(pedge, rem_id);
  }

  void ConnectionManager::CreateConnection(QSharedPointer<Edge> pedge,
      const Id &rem_id)
  {
    Connection *con = new Connection(pedge, _local_id, rem_id);
    _con_tab.AddConnection(con);
    qDebug() << "Handle new connection:" << con->ToString();
    QObject::connect(con, SIGNAL(CalledDisconnect()), this, SLOT(HandleDisconnect()));
    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));
    emit NewConnection(con);
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
    if(con == 0) {
      return;
    }

    qDebug() << "Handle disconnect on: " << con->ToString();
    _con_tab.Disconnect(con);

    if(!con->GetEdge()->IsClosed()) {
      if(con->GetLocalId() != con->GetRemoteId()) {
        QVariantMap notification;
        notification["method"] = "CM::Disconnect";
        _rpc.SendNotification(notification, con);
      }

      con->GetEdge()->Close("Local disconnect request");
    }
  }

  void ConnectionManager::HandleDisconnected(const QString &reason)
  {
    Connection *con = qobject_cast<Connection *>(sender());
    qDebug() << "Edge disconnected now removing Connection: " << con->ToString()
      << ", because: " << reason;
    _con_tab.RemoveConnection(con);
  }

  void ConnectionManager::Disconnect(RpcRequest &notification)
  {
    Connection *con = dynamic_cast<Connection *>(notification.GetFrom());
    if(con == 0) {
      qWarning() << "Received DisconnectResponse from a non-connection: " << notification.GetFrom()->ToString();
      return;
    }

    qDebug() << "Received disconnect for: " << con->ToString();
    _con_tab.Disconnect(con);
    con->GetEdge()->Close("Remote disconnect");
  }

  void ConnectionManager::HandleEdgeClose(const QString &reason)
  {
    Edge *edge = qobject_cast<Edge *>(sender());
    _active_addrs.remove(edge->GetRemoteAddress());
    qDebug() << "Edge closed: " << edge->ToString() << reason;
    if(!_con_tab.RemoveEdge(edge)) {
      qWarning() << "Edge closed but no Edge found in CT:" << edge->ToString();
    }

    Connection *con = _con_tab.GetConnection(edge);
    if(con != 0) {
      con = _con_tab.GetConnection(con->GetRemoteId());
      if(con != 0) {
        con->Disconnect();
      }
    }

    if(!_closed) {
      return;
    }

    if(_con_tab.GetEdges().count() == 0) {
      emit Disconnected();
    }
  }
}
}
