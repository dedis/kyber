#include <QDataStream>

#include "Connections/Connection.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/EdgeListenerFactory.hpp"
#include "Utils/Timer.hpp"

#include "BasicGossip.hpp"

using Dissent::Transports::AddressFactory;
using Dissent::Transports::EdgeListenerFactory;
using Dissent::Utils::Timer;
using Dissent::Utils::TimerCallback;
using Dissent::Utils::TimerMethod;

namespace Dissent {
namespace Overlay {
  BasicGossip::BasicGossip(const Id &local_id,
      const QList<Address> &local_endpoints,
      const QList<Address> &remote_endpoints) :
    _local_endpoints(local_endpoints),
    _remote_endpoints(remote_endpoints),
    _started(false),
    _stopped(false),
    _local_id(local_id),
    _cm(_local_id, _rpc),
    _peer_list_inquire(this, &BasicGossip::PeerListInquire),
    _peer_list_response(this, &BasicGossip::PeerListResponse),
    _notify_peer(this, &BasicGossip::PeerListIncrementalUpdate),
    _bootstrap_event(0)
  {
    _rpc.Register(&_peer_list_inquire, "SN::PeerList");
    _rpc.Register(&_notify_peer, "SN::Update");
  }

  BasicGossip::~BasicGossip()
  {
    _rpc.Unregister("SN::PeerList");
    _rpc.Unregister("SN::Update");

    if(_bootstrap_event) {
      _bootstrap_event->Stop();
      delete _bootstrap_event;
    }
  }

  bool BasicGossip::Start()
  {
    if(_started) {
      return false;
    }

    qDebug() << "Starting node" << _local_id.ToString();

    _started = true;

    QObject::connect(&_cm, SIGNAL(NewConnection(Connection *)),
        this, SLOT(HandleConnection(Connection *)));
    QObject::connect(&_cm, SIGNAL(ConnectionAttemptFailure(const Address &, const QString &)),
        this, SLOT(HandleConnectionAttemptFailure(const Address &, const QString &)));
    QObject::connect(&_cm, SIGNAL(Disconnected()),
        this, SLOT(HandleDisconnected()));

    foreach(const Address &addr, _local_endpoints) {
      EdgeListener *el = EdgeListenerFactory::GetInstance().CreateEdgeListener(addr);
      QSharedPointer<EdgeListener> pel(el);
      _edge_listeners.append(pel);
      _cm.AddEdgeListener(pel);
      pel->Start();
    }

    Bootstrap(0);
    return true;
  }

  bool BasicGossip::Stop()
  {
    if(_stopped) {
      return false;
    }

    _stopped = true;

    if(!_started) {
      _started = true;
      return false;
    }

    _cm.Disconnect();
    return true;
  }

  void BasicGossip::HandleDisconnected()
  {
    emit Disconnected();
  }

  bool BasicGossip::NeedConnection()
  {
    return _cm.GetConnectionTable().GetConnections().count() == 1;
  }

  void BasicGossip::HandleConnection(Connection *con)
  {
    _active_attempts.remove(con->GetEdge()->GetRemotePersistentAddress());
    SendUpdate(con);
    RequestPeerList(con);
    emit NewConnection(con);
  }

  void BasicGossip::HandleConnectionAttemptFailure(const Address &addr, const QString &)
  {
    _active_attempts.remove(addr);
    if(_active_attempts.count() > 0) {
      return;
    }

    if(_bootstrap_event == 0) {
      TimerCallback *cb = new TimerMethod<BasicGossip, int>(this, &BasicGossip::Bootstrap, 0);
      _bootstrap_event = new TimerEvent(Timer::GetInstance().QueueCallback(cb, 0, 5000));
    }
  }

  void BasicGossip::Bootstrap(const int &)
  {
    if(!NeedConnection()) {
      if(_bootstrap_event) {
        _bootstrap_event->Stop();
        delete _bootstrap_event;
        _bootstrap_event = 0;
      }
      return;
    }
    foreach(const Address &addr, _remote_endpoints) {
      ConnectTo(addr);
    }
  }

  void BasicGossip::SendUpdate(Connection *con)
  {
    QVariantMap notification;
    notification["method"] = "SN::Update";
    notification["peer_id"] = con->GetRemoteId().GetByteArray();
    notification["address"] = con->GetEdge()->GetRemotePersistentAddress().GetUrl();

    foreach(Connection *other_con, _cm.GetConnectionTable().GetConnections()) {
      if(other_con == con || other_con->GetRemoteId() == GetId()) {
        continue;
      }
      _rpc.SendNotification(notification, other_con);
    }
  }

  void BasicGossip::RequestPeerList(Connection *con)
  {
    QVariantMap request;
    request["method"] = "SN::PeerList";
    request["peer_id"] = _cm.GetId().GetByteArray();

    QList<QUrl> local_addresses;
    foreach(QSharedPointer<EdgeListener> el, _edge_listeners) {
      local_addresses.append(el->GetAddress().GetUrl());
    }

    QByteArray lam;
    QDataStream stream(&lam, QIODevice::WriteOnly);
    stream << local_addresses;
    request["addresses"] = lam;

    _rpc.SendRequest(request, con, &_peer_list_response);
  }

  void BasicGossip::PeerListInquire(RpcRequest &request)
  {
    QVariantMap msg = request.GetMessage();
    QByteArray bid = msg["peer_id"].toByteArray();

    QDataStream in_stream(msg["addresses"].toByteArray());
    QList<QUrl> addresses;
    in_stream >> addresses;

    foreach(QUrl url, addresses) {
      CheckAndConnect(bid, url);
    }

    QHash<QByteArray, QUrl> id_to_addr;
    foreach(Connection *con, _cm.GetConnectionTable().GetConnections()) {
      if(con->GetRemoteId() == GetId()) {
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

  void BasicGossip::PeerListResponse(RpcRequest &response)
  {
    QVariantMap msg = response.GetMessage();

    QDataStream stream(msg["peer_list"].toByteArray());
    QHash<QByteArray, QUrl> id_to_addr;
    stream >> id_to_addr;

    foreach(const QByteArray &bid, id_to_addr.keys()) {
      CheckAndConnect(bid, id_to_addr[bid]);
    }
  }

  void BasicGossip::PeerListIncrementalUpdate(RpcRequest &notification)
  {
    QVariantMap msg = notification.GetMessage();
    CheckAndConnect(msg["peer_id"].toByteArray(), msg["address"].toUrl());
  }

  void BasicGossip::CheckAndConnect(const QByteArray &bid, const QUrl &url)
  {
    if(!url.isValid()) {
      qWarning() << "Remote peer gave us an invalid url:" << url;
      return;
    }

    Id id(bid);
    if(_cm.GetConnectionTable().GetConnection(id) != 0) {
      return;
    }

    if(_local_id == id) {
      return;
    }

    Address addr = AddressFactory::GetInstance().CreateAddress(url);
    ConnectTo(addr);
  }

  void BasicGossip::ConnectTo(const Address &addr)
  {
    foreach(QSharedPointer<EdgeListener> el, _edge_listeners) {
      if(addr == el->GetAddress()) {
        return;
      }
    }

    if(_active_attempts.contains(addr)) {
      return;
    }
    _active_attempts[addr] = true;
    _cm.ConnectTo(addr);
  }
}
}
