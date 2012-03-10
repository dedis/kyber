#include "Messaging/RequestHandler.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Transports/AddressFactory.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "Connection.hpp"
#include "ConnectionManager.hpp"

namespace Dissent {
using Transports::AddressFactory;
using Messaging::RequestHandler;

namespace Connections {
  bool ConnectionManager::UseTimer = true;
  const int ConnectionManager::TimeBetweenEdgeCheck = 10000;
  const int ConnectionManager::EdgeCheckTimeout = 30000;
  const int ConnectionManager::EdgeCloseTimeout = 60000;

  ConnectionManager::ConnectionManager(const Id &local_id,
      const QSharedPointer<RpcHandler> &rpc) :
    _inquired(new ResponseHandler(this, "Inquired")),
    _ping_handler(new ResponseHandler(this, "HandlePingResponse")),
    _con_tab(local_id),
    _local_id(local_id),
    _rpc(rpc)
  {
    QSharedPointer<RequestHandler> inquire(
        new RequestHandler(this, "Inquire"));
    _rpc->Register("CM::Inquire", inquire);

    QSharedPointer<RequestHandler> close(
        new RequestHandler(this, "Close"));
    _rpc->Register("CM::Close", close);

    QSharedPointer<RequestHandler> connect(
        new RequestHandler(this, "Connect"));
    _rpc->Register("CM::Connect", connect);

    QSharedPointer<RequestHandler> disconnect(
        new RequestHandler(this, "Disconnect"));
    _rpc->Register("CM::Disconnect", disconnect);

    _rpc->Register("CM::Ping", this, "HandlePingRequest");

    QSharedPointer<Connection> con = _con_tab.GetConnection(_local_id);
    con->SetSink(_rpc.data());
    QObject::connect(con->GetEdge().data(), SIGNAL(StoppedSignal()),
        this, SLOT(HandleEdgeClose()));

    QObject::connect(con.data(), SIGNAL(CalledDisconnect()),
        this, SLOT(HandleDisconnect()));

    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));
  }

  ConnectionManager::~ConnectionManager()
  {
    _rpc->Unregister("CM::Inquire");
    _rpc->Unregister("CM::Close");
    _rpc->Unregister("CM::Connect");
    _rpc->Unregister("CM::Disconnect");
    _rpc->Unregister("CM::Ping");
  }

  void ConnectionManager::AddEdgeListener(const QSharedPointer<EdgeListener> &el)
  {
    if(Stopped()) {
      qWarning() << "Attempting to add an EdgeListener after calling Disconnect.";
      return;
    }

    _edge_factory.AddEdgeListener(el);

    QObject::connect(el.data(), SIGNAL(NewEdge(const QSharedPointer<Edge> &)),
        this, SLOT(HandleNewEdge(const QSharedPointer<Edge> &)));

    QObject::connect(el.data(),
        SIGNAL(EdgeCreationFailure(const Address &, const QString &)),
        this,
        SLOT(HandleEdgeCreationFailure(const Address &, const QString&)));
  }

  void ConnectionManager::ConnectTo(const Address &addr)
  {
    if(Stopped()) {
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

  void ConnectionManager::OnStart()
  {
    if(UseTimer) {
      qDebug() << "Starting timer";
      Utils::TimerCallback *cb =
        new Utils::TimerMethod<ConnectionManager, int>(this,
            &ConnectionManager::EdgeCheck, 0);
      _edge_check = Utils::Timer::GetInstance().QueueCallback(cb,
          TimeBetweenEdgeCheck, TimeBetweenEdgeCheck);
    }
  }

  void ConnectionManager::OnStop()
  {
    _edge_check.Stop();
    bool emit_dis = (_con_tab.GetEdges().count() == 0);

    foreach(const QSharedPointer<Connection> &con, _con_tab.GetConnections()) {
      con->Disconnect();
    }

    foreach(const QSharedPointer<Edge> &edge, _con_tab.GetEdges()) {
      edge->Stop("Disconnecting");
    }
    
    _edge_factory.Stop();

    if(emit_dis) {
      emit Disconnected();
    } 
  }

  void ConnectionManager::HandleNewEdge(const QSharedPointer<Edge> &edge)
  {
    _con_tab.AddEdge(edge);
    edge->SetSink(_rpc.data());

    QObject::connect(edge.data(), SIGNAL(StoppedSignal()),
        this, SLOT(HandleEdgeClose()));

    if(!edge->Outbound()) {
      return;
    }

    _outstanding_con_attempts.remove(edge->GetRemoteAddress());
    if(!_active_addrs.contains(edge->GetRemoteAddress())) {
      qDebug() << "No record of attempting connection to" <<
        edge->GetRemoteAddress().ToString();
    }

    QVariantHash request;
    request["peer_id"] = _local_id.GetByteArray();

    QString type = edge->GetLocalAddress().GetType();
    QSharedPointer<EdgeListener> el = _edge_factory.GetEdgeListener(type);
    request["persistent"] = el->GetAddress().ToString();

    _rpc->SendRequest(edge, "CM::Inquire", request, _inquired);
  }

  void ConnectionManager::EdgeCheck(const int &)
  {
    qDebug() << "Checking edges";
    QList<QSharedPointer<Edge> > edges_to_close;
    qint64 now = Utils::Time::GetInstance().MSecsSinceEpoch();
    qint64 check_time = now - EdgeCheckTimeout;
    qint64 close_time = now - EdgeCloseTimeout;

    foreach(const QSharedPointer<Edge> &edge, _con_tab.GetEdges()) {
      qint64 last_msg = edge->GetLastIncomingMessage();
      if(check_time < last_msg) {
        continue;
      } else if(last_msg < close_time) {
        qDebug() << "Closing edge:" << edge->ToString();
        edge->Stop("Timed out");
      } else {
        qDebug() << "Testing edge:" << edge->ToString();
        QSharedPointer<Messaging::ISender> sender = _con_tab.GetConnection(edge.data());
        if(!sender) {
          sender = edge;
        }
        _rpc->SendRequest(sender, "CM::Ping", QVariant(), _ping_handler, true);
      }
    }
  }

  void ConnectionManager::HandlePingRequest(const Request &request)
  {
    request.Respond(request.GetData());
  }

  void ConnectionManager::HandlePingResponse(const Response &)
  {
  }

  void ConnectionManager::HandleEdgeCreationFailure(const Address &to,
      const QString &reason)
  {
    _active_addrs.remove(to);
    _outstanding_con_attempts.remove(to);
    emit ConnectionAttemptFailure(to, reason);
  }

  void ConnectionManager::Inquire(const Request &request)
  {
    QSharedPointer<Edge> edge = request.GetFrom().dynamicCast<Edge>();
    if(!edge) {
      qWarning() << "Received an inquired from a non-Edge: " <<
        request.GetFrom()->ToString();
      return;
    } else if(edge->Outbound()) {
      qWarning() << "We should never receive an inquire call on an" <<
        "outbound edge: " << request.GetFrom()->ToString();
      return;
    }

    QVariantHash data = request.GetData().toHash();
    QByteArray brem_id = data.value("peer_id").toByteArray();

    if(brem_id.isEmpty()) {
      qWarning() << "Invalid Inquire, no id";
      return;
    }

    Id rem_id(brem_id);

    request.Respond(_local_id.GetByteArray());

    QString saddr = data.value("persistent").toString();
    Address addr = AddressFactory::GetInstance().CreateAddress(saddr);
    edge->SetRemotePersistentAddress(addr);

    if(_local_id < rem_id) {
      BindEdge(edge, rem_id);
    } else if(_local_id == rem_id) {
      edge->Stop("Attempting to connect to ourself");
    }
  }

  void ConnectionManager::Inquired(const Response &response)
  {
    QSharedPointer<Edge> edge = response.GetFrom().dynamicCast<Edge>();
    if(!edge) {
      qWarning() << "Received an inquired from a non-Edge: " <<
        response.GetFrom()->ToString();
      return;
    } else if(!edge->Outbound()) {
      qWarning() << "We would never make an inquire call on an" <<
        "incoming edge: " << response.GetFrom()->ToString();
      return;
    }

    QByteArray brem_id = response.GetData().toByteArray();
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
      edge->Stop("Attempting to connect to ourself");
      emit ConnectionAttemptFailure(addr, "Attempting to connect to ourself");
    }
  }

  void ConnectionManager::BindEdge(const QSharedPointer<Edge> &edge,
      const Id &rem_id)
  {
    /// @TODO add an extra variable to the connection message such as a session
    ///token so that quick reconnects can be enabled.
    if(_con_tab.GetConnection(rem_id) != 0) {
      qDebug() << "Already have a connection to: " << rem_id.ToString() << 
        " closing Edge: " << edge->ToString();

      _rpc->SendNotification(edge, "CM::Close", QVariant());
      Address addr = edge->GetRemoteAddress();
      edge->Stop("Duplicate connection");
      emit ConnectionAttemptFailure(addr, "Duplicate connection");
      return;
    }
  
    _rpc->SendNotification(edge, "CM::Connect", _local_id.GetByteArray());
    CreateConnection(edge, rem_id);
  }

  void ConnectionManager::Connect(const Request &notification)
  {
    QSharedPointer<Edge> edge = notification.GetFrom().dynamicCast<Edge>();
    if(!edge) {
      qWarning() << "Connection attempt not from an Edge: " <<
        notification.GetFrom()->ToString();
      return;
    }
    
    QByteArray brem_id = notification.GetData().toByteArray();
    if(brem_id.isEmpty()) {
      qWarning() << "Invalid ConnectionEstablished, no id";
      return;
    }

    Id rem_id(brem_id);
    if(_local_id < rem_id) {
      qWarning() << "We should be sending CM::Connect, not the remote side.";
      return;
    }

    QSharedPointer<Connection> old_con = _con_tab.GetConnection(rem_id);
    // XXX if there is an old connection and the node doesn't want it, we need
    // to close it
    if(old_con) {
      qDebug() << "Disconnecting old connection";
      old_con->Disconnect();
    }

    CreateConnection(edge, rem_id);
  }

  void ConnectionManager::CreateConnection(const QSharedPointer<Edge> &pedge,
      const Id &rem_id)
  {
    QSharedPointer<Connection> con(new Connection(pedge, _local_id, rem_id),
        &QObject::deleteLater);
    con->SetSharedPointer(con);
    _con_tab.AddConnection(con);
    qDebug() << "Handle new connection:" << con->ToString();

    QObject::connect(con.data(), SIGNAL(CalledDisconnect()),
        this, SLOT(HandleDisconnect()));

    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnected(const QString &)));

    emit NewConnection(con);
  }

  void ConnectionManager::Close(const Request &notification)
  {
    QSharedPointer<Edge> edge = notification.GetFrom().dynamicCast<Edge>();
    if(!edge) {
      qWarning() << "Connection attempt Edge close not from an Edge: " <<
        notification.GetFrom()->ToString();
      return;
    }

    edge->Stop("Closed from remote peer");
  }

  void ConnectionManager::HandleDisconnect()
  {
    Connection *con = qobject_cast<Connection *>(sender());
    if(con == 0) {
      return;
    }

    qDebug() << "Handle disconnect on: " << con->ToString();
    _con_tab.Disconnect(con);

    if(!con->GetEdge()->Stopped()) {
      if(con->GetLocalId() != con->GetRemoteId()) {
        _rpc->SendNotification(con->GetSharedPointer(),
            "CM::Disconnect", QVariant());
      }

      con->GetEdge()->Stop("Local disconnect request");
    }
  }

  void ConnectionManager::HandleDisconnected(const QString &reason)
  {
    Connection *con = qobject_cast<Connection *>(sender());
    qDebug() << "Edge disconnected now removing Connection: " << con->ToString()
      << ", because: " << reason;
    _con_tab.RemoveConnection(con);
  }

  void ConnectionManager::Disconnect(const Request &notification)
  {
    QSharedPointer<Connection> con =
      notification.GetFrom().dynamicCast<Connection>();

    if(!con) {
      qWarning() << "Received DisconnectResponse from a non-connection: " <<
        notification.GetFrom()->ToString();
      return;
    }

    qDebug() << "Received disconnect for: " << con->ToString();
    _con_tab.Disconnect(con.data());
    con->GetEdge()->Stop("Remote disconnect");
  }

  void ConnectionManager::HandleEdgeClose()
  {
    Edge *edge = qobject_cast<Edge *>(sender());
    _active_addrs.remove(edge->GetRemoteAddress());
    qDebug() << "Edge closed: " << edge->ToString() << edge->GetStopReason();
    if(!_con_tab.RemoveEdge(edge)) {
      qWarning() << "Edge closed but no Edge found in CT:" << edge->ToString();
    }

    QSharedPointer<Connection> con = _con_tab.GetConnection(edge);
    if(con) {
      con = _con_tab.GetConnection(con->GetRemoteId());
      if(con) {
        con->Disconnect();
      }
    }

    if(!Stopped()) {
      return;
    }

    if(_con_tab.GetEdges().count() == 0) {
      emit Disconnected();
    }
  }
}
}
