#include <QSharedPointer>
#include <QVariant>

#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Transports/AddressFactory.hpp"
#include "Utils/Random.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/Timer.hpp"

#include "Connection.hpp"
#include "FullyConnected.hpp"

using Dissent::Utils::Timer;
using Dissent::Utils::TimerCallback;

namespace Dissent {
namespace Connections {
  FullyConnected::FullyConnected(const QSharedPointer<ConnectionManager> &cm,
      const QSharedPointer<RpcHandler> &rpc) :
    ConnectionAcquirer(cm),
    _rpc(rpc),
    _relay_el(new RelayEdgeListener(cm->GetId(), cm->GetConnectionTable(), rpc)),
    _peer_list_response(new ResponseHandler(this, "PeerListResponse"))
  {
    cm->AddEdgeListener(_relay_el);
    _rpc->Register("FC::PeerList", this, "PeerListInquire");
    _rpc->Register("FC::Update", this, "PeerListIncrementalUpdate");
  }

  FullyConnected::~FullyConnected()
  {
    _rpc->Unregister("FC::PeerList");
    _rpc->Unregister("FC::Update");
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

  void FullyConnected::HandleConnection(const QSharedPointer<Connection> &con)
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

  void FullyConnected::SendUpdate(const QSharedPointer<Connection> &con)
  {
    QVariantHash msg;
    msg["peer_id"] = con->GetRemoteId().GetByteArray();
    msg["address"] = con->GetEdge()->GetRemotePersistentAddress().GetUrl();

    const Id &my_id = GetConnectionManager()->GetId();
    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();

    foreach(const QSharedPointer<Connection> &other_con, ct.GetConnections()) {
      if((other_con == con) || (other_con->GetRemoteId() == my_id)) {
        continue;
      }
      GetRpcHandler()->SendNotification(other_con, "FC::Update", msg);
    }
  }

  void FullyConnected::RequestPeerList(const QSharedPointer<Connection> &con)
  {
    GetRpcHandler()->SendRequest(con, "FC::PeerList", QVariant(),
        _peer_list_response);
  }

  void FullyConnected::PeerListInquire(const Request &request)
  {
    QHash<QByteArray, QUrl> id_to_addr;
    const Id &my_id = GetConnectionManager()->GetId();
    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();

    foreach(const QSharedPointer<Connection> &con, ct.GetConnections()) {
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

    request.Respond(plm);
  }

  void FullyConnected::PeerListResponse(const Response &response)
  {
    QDataStream stream(response.GetData().toByteArray());
    QHash<QByteArray, QUrl> id_to_addr;
    stream >> id_to_addr;

    foreach(const QByteArray &bid, id_to_addr.keys()) {
      CheckAndConnect(bid, id_to_addr[bid]);
    }
  }

  void FullyConnected::PeerListIncrementalUpdate(const Request &notification)
  {
    QVariantHash msg = notification.GetData().toHash();
    CheckAndConnect(msg.value("peer_id").toByteArray(),
        msg.value("address").toUrl());
  }

  void FullyConnected::CheckAndConnect(const QByteArray &bid, const QUrl &url)
  {
    if(!url.isValid()) {
      qWarning() << "Remote peer gave us an invalid url:" << url;
      return;
    }

    Id id(bid);
    if(GetConnectionManager()->GetConnectionTable().GetConnection(id) != 0) {
      return;
    }

    if(GetConnectionManager()->GetId() == id) {
      return;
    }

    Address addr = Dissent::Transports::AddressFactory::GetInstance().CreateAddress(url);
    if(_waiting_on.contains(addr) || (addr.GetType() == RelayAddress::Scheme)) {
      return;
    }
    _waiting_on[addr] = id;
    GetConnectionManager()->ConnectTo(addr);
  }

  void FullyConnected::RequestPeerList(const int &)
  {
    Dissent::Utils::Random &rand = Dissent::Utils::Random::GetInstance();
    const QList<QSharedPointer<Connection> > &cons =
      GetConnectionManager()->GetConnectionTable().GetConnections();

    int idx = rand.GetInt(0, cons.size());
    while(cons[idx]->GetRemoteId() == GetConnectionManager()->GetId()) {
      idx = rand.GetInt(0, cons.size());
    }
    RequestPeerList(cons[idx]);
  }
}
}
