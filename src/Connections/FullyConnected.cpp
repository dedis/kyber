#include <QVariant>

#include "Transports/AddressFactory.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/Timer.hpp"

#include "Connection.hpp"
#include "FullyConnected.hpp"

using Dissent::Utils::Timer;
using Dissent::Utils::TimerCallback;

namespace Dissent {
namespace Connections {
  FullyConnected::FullyConnected(ConnectionManager &cm, RpcHandler &rpc) :
    ConnectionAcquirer(cm),
    _rpc(rpc),
    _relay_el(new RelayEdgeListener(cm.GetId(), cm.GetConnectionTable(), rpc)),
    _peer_list_inquire(this, &FullyConnected::PeerListInquire),
    _peer_list_response(this, &FullyConnected::PeerListResponse),
    _notify_peer(this, &FullyConnected::PeerListIncrementalUpdate)
  {
    cm.AddEdgeListener(_relay_el);
    _rpc.Register(&_peer_list_inquire, "FC::PeerList");
    _rpc.Register(&_notify_peer, "FC::Update");
  }

  FullyConnected::~FullyConnected()
  {
    _rpc.Unregister("FC::PeerList");
    _rpc.Unregister("FC::Update");
  }

  void FullyConnected::OnStart()
  {
     TimerCallback *cb = new Dissent::Utils::TimerMethod<FullyConnected, int>(
         this, &FullyConnected::RequestPeerList, -1);
     _check_event = new TimerEvent(Timer::GetInstance().QueueCallback(cb, 60000, 60000));
  }

  void FullyConnected::OnStop()
  {
    if(_check_event != 0) {
      _check_event->Stop();
      delete _check_event;
      _check_event = 0;
    }
  }

  void FullyConnected::HandleConnection(Connection *con)
  {
    _waiting_on.remove(con->GetEdge()->GetRemotePersistentAddress());
    SendUpdate(con);
    RequestPeerList(con);
  }

  void FullyConnected::HandleConnectionAttemptFailure(const Address &addr,
          const QString &)
  {
    if(!_waiting_on.contains(addr)) {
      return;
    }
    Id id = _waiting_on[addr];
    _waiting_on.remove(addr);

    qDebug() << "Unable to create a direct connection to" << id.ToString() <<
      "(" << addr.ToString() << ") trying via relay.";
    _relay_el->CreateEdgeTo(id);
  }

  void FullyConnected::HandleDisconnect(const QString &)
  {
  }

  void FullyConnected::SendUpdate(Connection *con)
  {
    QVariantMap notification;
    notification["method"] = "FC::Update";
    notification["peer_id"] = con->GetRemoteId().GetByteArray();
    notification["address"] = con->GetEdge()->GetRemotePersistentAddress().GetUrl();

    const Id &my_id = GetConnectionManager().GetId();
    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();

    foreach(Connection *other_con, ct.GetConnections()) {
      if((other_con == con) || (other_con->GetRemoteId() == my_id)) {
        continue;
      }
      GetRpcHandler().SendNotification(notification, other_con);
    }
  }

  void FullyConnected::RequestPeerList(Connection *con)
  {
    QVariantMap request;
    request["method"] = "FC::PeerList";
    GetRpcHandler().SendRequest(request, con, &_peer_list_response);
  }

  void FullyConnected::PeerListInquire(RpcRequest &request)
  {
    QHash<QByteArray, QUrl> id_to_addr;
    const Id &my_id = GetConnectionManager().GetId();
    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();

    foreach(Connection *con, ct.GetConnections()) {
      if(con->GetRemoteId() == my_id) {
        continue;
      }

      QUrl url = con->GetEdge()->GetRemotePersistentAddress().GetUrl();
      QByteArray id = con->GetRemoteId().GetByteArray();
      id_to_addr[id] = url;
    }

    QByteArray plm;
    QDataStream out_stream(&plm, QIODevice::WriteOnly);
    out_stream << id_to_addr;

    QVariantMap response;
    response["peer_list"] = plm;
    request.Respond(response);
  }

  void FullyConnected::PeerListResponse(RpcRequest &response)
  {
    QVariantMap msg = response.GetMessage();

    QDataStream stream(msg["peer_list"].toByteArray());
    QHash<QByteArray, QUrl> id_to_addr;
    stream >> id_to_addr;

    foreach(const QByteArray &bid, id_to_addr.keys()) {
      CheckAndConnect(bid, id_to_addr[bid]);
    }
  }

  void FullyConnected::PeerListIncrementalUpdate(RpcRequest &notification)
  {
    QVariantMap msg = notification.GetMessage();
    CheckAndConnect(msg["peer_id"].toByteArray(), msg["address"].toUrl());
  }

  void FullyConnected::CheckAndConnect(const QByteArray &bid, const QUrl &url)
  {
    if(!url.isValid()) {
      qWarning() << "Remote peer gave us an invalid url:" << url;
      return;
    }

    Id id(bid);
    if(GetConnectionManager().GetConnectionTable().GetConnection(id) != 0) {
      return;
    }

    if(GetConnectionManager().GetId() == id) {
      return;
    }

    Address addr = Dissent::Transports::AddressFactory::GetInstance().CreateAddress(url);
    if(_waiting_on.contains(addr) || (addr.GetType() == RelayAddress::Scheme)) {
      return;
    }
    _waiting_on[addr] = id;
    GetConnectionManager().ConnectTo(addr);
  }

  void FullyConnected::RequestPeerList(const int &)
  {
    Dissent::Utils::Random &rand = Dissent::Utils::Random::GetInstance();
    const QList<Connection *> &cons =
      GetConnectionManager().GetConnectionTable().GetConnections();

    int idx = rand.GetInt(0, cons.size());
    while(cons[idx]->GetRemoteId() == GetConnectionManager().GetId()) {
      idx = rand.GetInt(0, cons.size());
    }
    RequestPeerList(cons[idx]);
  }
}
}
