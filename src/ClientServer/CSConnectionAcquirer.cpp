#include "Connections/Connection.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Library.hpp"
#include "Transports/AddressFactory.hpp"
#include "Utils/Random.hpp"
#include "Utils/Timer.hpp"

#include "CSConnectionAcquirer.hpp"

using Dissent::Identity::GroupContainer;
using Dissent::Connections::ConnectionTable;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Utils::Random;
using Dissent::Utils::Timer;
using Dissent::Utils::TimerCallback;

namespace Dissent {
namespace ClientServer {
  CSConnectionAcquirer::CSConnectionAcquirer(ConnectionManager &cm,
      RpcHandler &rpc, const Group &group) :
    ConnectionAcquirer(cm),
    _bootstrapping(true),
    _group(group),
    _rpc(rpc),
    _server_state_request(this,
        &CSConnectionAcquirer::ServerStateInquire),
    _server_state_response(this,
        &CSConnectionAcquirer::ServerStateResponse)
  {
    _rpc.Register(&_server_state_request, "CSCA::ServerList");
  }

  CSConnectionAcquirer::~CSConnectionAcquirer()
  {
    _rpc.Unregister("CSCA::ServerList");
  }

  void CSConnectionAcquirer::OnStart()
  {
    TimerCallback *cb = new Dissent::Utils::TimerMethod<CSConnectionAcquirer, int>(
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

  void CSConnectionAcquirer::HandleConnection(Connection *con)
  {
    Id remote = con->GetRemoteId();
    if(!_group.GetSubgroup().Contains(remote) && _group.GetLeader() != remote &&
        GetConnectionManager().GetConnectionTable().GetConnections().size() == 2)
    {
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
    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();
    if(ct.GetConnections().size() == 1) {
      return;
    }

    foreach(const GroupContainer &gc, _group.GetSubgroup()) {
      if(gc.first == GetConnectionManager().GetId()) {
        continue;
      }
      Connection *con = ct.GetConnection(gc.first);
      if(con != 0) {
        RequestServerState(con);
        return;
      }
    }

    foreach(Connection *con, ct.GetConnections()) {
      if(con->GetRemoteId() == GetConnectionManager().GetId()) {
        continue;
      }
      RequestServerState(con);
      return;
    }
  }

  void CSConnectionAcquirer::RequestServerState(Connection *con)
  {
    Dissent::Messaging::RpcContainer request;
    request["method"] = "CSCA::ServerList";
    _rpc.SendRequest(request, con, &_server_state_response);
  }

  void CSConnectionAcquirer::ServerStateInquire(RpcRequest &request)
  {
    QHash<QByteArray, QUrl> id_to_addr;
    const Id &my_id = GetConnectionManager().GetId();
    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();

    foreach(const GroupContainer &gc, _group.GetSubgroup()) {
      const Id &gc_id = gc.first;
      if(gc_id == my_id) {
        continue;
      }

      Connection *con = ct.GetConnection(gc_id);
      if(con == 0) {
        continue;
      }

      id_to_addr[gc_id.GetByteArray()] =
        con->GetEdge()->GetRemotePersistentAddress().GetUrl();
    }

    QByteArray slm;
    QDataStream out_stream(&slm, QIODevice::WriteOnly);
    out_stream << id_to_addr;

    Dissent::Messaging::RpcContainer response;
    response["connections"] = ct.GetConnections().size();
    response["list"] = slm;
    request.Respond(response);
  }

  void CSConnectionAcquirer::ServerStateResponse(RpcRequest &response)
  {
    Dissent::Messaging::RpcContainer msg = response.GetMessage();

    Connection *con = dynamic_cast<Connection *>(response.GetFrom());
    if(con == 0) {
      qCritical() << "Received an rpc request from a non-connection.";
      return;
    }
    Id remote = con->GetRemoteId();

    QHash<QByteArray, QUrl> id_to_addr;
    QDataStream stream(msg["list"].toByteArray());
    stream >> id_to_addr;
    int cons = msg["connections"].toInt();

    if(_group.GetSubgroup().Contains(GetConnectionManager().GetId())) {
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

    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();
    foreach(const GroupContainer &gc, _group.GetSubgroup()) {
      if(ct.GetConnection(gc.first) != 0) {
        return;
      }
    }

    QSharedPointer<Random> rand(CryptoFactory::GetInstance().
      GetLibrary()->GetRandomNumberGenerator());

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
    const ConnectionTable &ct = GetConnectionManager().GetConnectionTable();
    Id id(bid);

    if(id == Id::Zero()) {
      qDebug() << "Found a malformed Id";
      return false;
    } else if(id == GetConnectionManager().GetId()) {
      // It is me
      return false;
    } else if(ct.GetConnection(id) != 0) {
      // Already connected
      return false;
    } else if(!_group.GetSubgroup().Contains(id)) {
      qWarning() << "Found a connection in another servers list that is not a"
        << "server in my own list:" << id.ToString();
      return false;
    }

    if(!url.isValid()) {
      qWarning() << "Remote gave us an invalid url:" << url;
      return false;
    }

    Address addr = Dissent::Transports::AddressFactory::GetInstance().CreateAddress(url);
    GetConnectionManager().ConnectTo(addr);
    _local_initiated[id] = true;
    _addr_to_id[addr] = id;
    return true;
  }
}
}
