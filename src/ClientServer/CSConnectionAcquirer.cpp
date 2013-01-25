#include "Connections/Connection.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Library.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Transports/AddressFactory.hpp"
#include "Utils/Random.hpp"
#include "Utils/Timer.hpp"

#include "CSConnectionAcquirer.hpp"

namespace Dissent {

using Identity::PublicIdentity;
using Connections::ConnectionTable;
using Crypto::CryptoFactory;
using Crypto::Library;
using Utils::Random;
using Utils::Timer;
using Utils::TimerCallback;

namespace ClientServer {
  CSConnectionAcquirer::CSConnectionAcquirer(
      const QSharedPointer<ConnectionManager> &cm,
      const QSharedPointer<RpcHandler> &rpc, const Group &group) :
    ConnectionAcquirer(cm),
    _bootstrapping(true),
    _group(group),
    _rpc(rpc),
    _server_state_response(new ResponseHandler(this, "ServerStateResponse"))
  {
    _rpc->Register("CSCA::ServerList", this, "ServerStateInquire");
  }

  CSConnectionAcquirer::~CSConnectionAcquirer()
  {
    _rpc->Unregister("CSCA::ServerList");
  }

  void CSConnectionAcquirer::OnStart()
  {
    TimerCallback *cb = new Utils::TimerMethod<CSConnectionAcquirer, int>(
        this, &CSConnectionAcquirer::RequestServerState, -1);
    _check_event = new TimerEvent(Timer::GetInstance().QueueCallback(cb, 120000, 120000));
  }

  void CSConnectionAcquirer::OnStop()
  {
    if(_check_event != 0) {
      _check_event->Stop();
      delete _check_event;
      _check_event = 0;
    }
  }

  void CSConnectionAcquirer::HandleConnection(
      const QSharedPointer<Connection> &con)
  {
    Id remote = con->GetRemoteId();

    if(!IsServer() && _group.GetSubgroup().Contains(remote)) {
      _bootstrapping = false;
      return;
    }

    Address addr = con->GetEdge()->GetRemotePersistentAddress();
    if(_addr_to_id.contains(addr)) {
      _addr_to_id.remove(addr);
    }

    RequestServerState(con);
  }

  void CSConnectionAcquirer::UpdateGroup(const Group &group)
  {
    _group = group;

    if(!IsServer()) {
      return;
    }

    if(!IsServer() && !_bootstrapping) {
      return;
    }

    foreach(const PublicIdentity &gc, _group.GetSubgroup()) {
      if(GetConnectionManager()->GetConnectionTable().GetConnection(gc.GetId())) {
        continue;
      }
      RequestServerState();
      break;
    }
  }

  void CSConnectionAcquirer::HandleConnectionAttemptFailure(
      const Address &addr, const QString &)
  {
    if(!_addr_to_id.contains(addr)) {
      return;
    }

    Id id = _addr_to_id[addr];
    _addr_to_id.remove(addr);
    _local_initiated.remove(id);
  }

  void CSConnectionAcquirer::RequestServerState(const int &)
  {
    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();
    if(ct.GetConnections().size() == 1) {
      return;
    }

    foreach(const PublicIdentity &gc, _group.GetSubgroup()) {
      if(gc.GetId() == GetConnectionManager()->GetId()) {
        continue;
      }
      QSharedPointer<Connection> con = ct.GetConnection(gc.GetId());
      if(con != 0) {
        RequestServerState(con);
        return;
      }
    }

    foreach(const QSharedPointer<Connection> &con, ct.GetConnections()) {
      if(con->GetRemoteId() == GetConnectionManager()->GetId()) {
        continue;
      }
      RequestServerState(con);
      return;
    }
  }

  void CSConnectionAcquirer::RequestServerState(
      const QSharedPointer<Connection> &con)
  {
    _rpc->SendRequest(con, "CSCA::ServerList", QVariant(),
        _server_state_response);
  }

  void CSConnectionAcquirer::ServerStateInquire(const Request &request)
  {
    QHash<QByteArray, QUrl> id_to_addr;
    const Id &my_id = GetConnectionManager()->GetId();
    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();

    foreach(const PublicIdentity &gc, _group.GetSubgroup()) {
      const Id &gc_id = gc.GetId();
      if(gc_id == my_id) {
        continue;
      }

      QSharedPointer<Connection> con = ct.GetConnection(gc_id);
      if(!con) {
        continue;
      }

      id_to_addr[gc_id.GetByteArray()] =
        con->GetEdge()->GetRemotePersistentAddress().GetUrl();
    }

    QByteArray slm;
    QDataStream out_stream(&slm, QIODevice::WriteOnly);
    out_stream << id_to_addr;

    QVariantHash msg;
    msg["connections"] = ct.GetConnections().size();
    msg["list"] = slm;
    request.Respond(msg);
  }

  void CSConnectionAcquirer::ServerStateResponse(const Response &response)
  {
    QSharedPointer<Connection> con =  response.GetFrom().dynamicCast<Connection>();
    if(!con) {
      qCritical() << "Received an rpc request from a non-connection.";
      return;
    }
    Id remote = con->GetRemoteId();

    QVariantHash msg = response.GetData().toHash();

    QHash<QByteArray, QUrl> id_to_addr;
    QDataStream stream(msg.value("list").toByteArray());
    stream >> id_to_addr;
    int cons = msg.value("connections").toInt();

    if(IsServer()) {
      ServerHandleServerStateResponse(remote, id_to_addr, cons);
    } else {
      ClientHandleServerStateResponse(remote, id_to_addr, cons);
    }
  }

  void CSConnectionAcquirer::ClientHandleServerStateResponse(
      const Id &, const QHash<QByteArray, QUrl> &id_to_addr, int)
  {
    if(id_to_addr.size() == 0) {
      return;
    }

    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();
    foreach(const PublicIdentity &gc, _group.GetSubgroup()) {
      if(ct.GetConnection(gc.GetId()) != 0) {
        return;
      }
    }

    QSharedPointer<Random> rand(CryptoFactory::GetInstance().
      GetLibrary().GetRandomNumberGenerator());

    QByteArray bid = id_to_addr.keys()[rand->GetInt(0, id_to_addr.size())];
    CheckAndConnect(bid, id_to_addr[bid]);
  }

  void CSConnectionAcquirer::ServerHandleServerStateResponse(
      const Id &, const QHash<QByteArray, QUrl> &id_to_addr, int)
  {
    foreach(const QByteArray &bid, id_to_addr.keys()) {
      CheckAndConnect(bid, id_to_addr[bid]);
    }
  }

  bool CSConnectionAcquirer::CheckAndConnect(const QByteArray &bid, const QUrl &url)
  {
    if(!IsServer()) {
      return false;
    }

    const ConnectionTable &ct = GetConnectionManager()->GetConnectionTable();
    Id id(bid);

    if(id == Id::Zero()) {
      qDebug() << "Found a malformed Id";
      return false;
    } else if(id == GetConnectionManager()->GetId()) {
      // It is me
      return false;
    } else if(ct.GetConnection(id) != 0) {
      // Already connected
      return false;
    } else if(!_group.GetSubgroup().Contains(id)) {
      if(_group.Contains(id)) {
        qWarning() << "Found a connection in another servers list that is not a"
          << "server in my own list:" << id.ToString();
      } else {
        qDebug() << "Found an unknown identity in another servers list:"
          << id.ToString() << "Must have stale info";
      }
      return false;
    }

    if(!url.isValid()) {
      qWarning() << "Remote gave us an invalid url:" << url;
      return false;
    }

    Address addr = Transports::AddressFactory::GetInstance().CreateAddress(url);
    GetConnectionManager()->ConnectTo(addr);
    _local_initiated[id] = true;
    _addr_to_id[addr] = id;
    return true;
  }
}
}
