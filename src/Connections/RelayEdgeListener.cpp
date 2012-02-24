#include "Utils/Random.hpp"

#include "RelayEdgeListener.hpp"

namespace Dissent {
namespace Connections {
  RelayEdgeListener::RelayEdgeListener(const Id &local_id,
      const ConnectionTable &ct, const QSharedPointer<RpcHandler> &rpc) :
    EdgeListener(RelayAddress(local_id)),
    _local_id(local_id),
    _ct(ct),
    _rpc(rpc),
    _forwarder(new RelayForwarder(local_id, ct, rpc)),
    _edge_created(new ResponseHandler(this, "EdgeCreated"))
  {
    _forwarder->SetSharedPointer(_forwarder);
    _rpc->Register("REL::CreateEdge", this, "CreateEdge");
    _rpc->Register("REL::Data", this, "IncomingData");
  }

  RelayEdgeListener::~RelayEdgeListener()
  {
    _rpc->Unregister("REL::CreateEdge");
    _rpc->Unregister("REL::Data");
  }

  void RelayEdgeListener::OnStart()
  {
    EdgeListener::OnStart();
  }

  void RelayEdgeListener::OnStop()
  {
    EdgeListener::OnStop();
  }

  void RelayEdgeListener::CreateEdgeTo(const Address &to)
  {
    qDebug() << "Some remote peer attempted to trick us into creating" <<
     "an edge to it:" << to.ToString();

    /* XXX maybe one day this will actually be utilized
    const RelayAddress &rto = static_cast<const RelayAddress &>(to);
    if(!rto.Valid()) {
      qWarning() << "Not a valid RelayAddress:" << to.ToString();
      return;
    }

    CreateEdgeTo(rto.GetId());
    */
  }

  void RelayEdgeListener::CreateEdgeTo(const Id &id, int times)
  {
    QVariantHash msg;
    msg["x_peer_id"] = _local_id.ToString();
    msg["y_peer_id"] = id.ToString();

    int edge_id = GetEdgeId();
    QSharedPointer<ISender> forwarder = _forwarder->GetSender(id);

    QSharedPointer<RelayEdge> redge(new RelayEdge(GetAddress(),
          RelayAddress(id), true, _rpc, forwarder, edge_id));
    redge->SetSharedPointer(redge);
    _edges[edge_id] = redge;
    msg["x_edge_id"] = edge_id;

    int req = _rpc->SendRequest(forwarder, "REL::CreateEdge",
        msg, _edge_created);

    TCallback *cb = new TCallback(this, &RelayEdgeListener::CheckEdge,
        CallbackData(req, id, times));
    Timer::GetInstance().QueueCallback(cb, 120000);
  }

  void RelayEdgeListener::CheckEdge(const CallbackData &data)
  {
    _rpc->CancelRequest(data.first);
    if(_ct.GetConnection(data.second) != 0) {
      return;
    }

    if(data.third < 5) {
      CreateEdgeTo(data.second, data.third + 1);
    } else {
      qDebug() << _local_id.ToString() << "failed to create a connection to" << data.second.ToString();
    }
  }

  void RelayEdgeListener::CreateEdge(const Request &request)
  {
    QVariantHash msg = request.GetData().toHash();

    Id remote_peer = Id(msg.value("x_peer_id").toString());
    if(remote_peer == Id::Zero()) {
      request.Failed(Response::InvalidInput, "Unparseable peerid");
      return;
    }

    bool ok;
    int x_edge_id = msg.value("x_edge_id").toInt(&ok);
    if(!ok) {
      request.Failed(Response::InvalidInput, "Invalid out_edge_id");
      return;
    }

    int y_edge_id = GetEdgeId();
    QSharedPointer<RelayEdge> redge(new RelayEdge(GetAddress(),
          RelayAddress(remote_peer), false, _rpc,
          request.GetFrom(), y_edge_id, x_edge_id));
    redge->SetSharedPointer(redge);

    _edges[y_edge_id] = redge;
    QVariantHash response;
    response["x_edge_id"] = y_edge_id;
    response["y_edge_id"] = x_edge_id;
    request.Respond(response);

    ProcessNewEdge(redge);
  }

  void RelayEdgeListener::EdgeCreated(const Response &response)
  {
    if(!response.Successful()) {
      qWarning() << "Received EdgeCreated but error on remote side:" <<
        response.GetError();
      return;
    }

    QVariantHash msg = response.GetData().toHash();

    bool ok;
    int x_edge_id = msg.value("x_edge_id").toInt(&ok);
    if(!ok) {
      qWarning() << "Received EdgeCreated but contains no from id.";
      return;
    }

    int y_edge_id = msg.value("y_edge_id").toInt(&ok);
    if(!ok) {
      qWarning() << "Received EdgeCreated but contains no to id.";
      return;
    }

    if(!_edges.contains(y_edge_id)) {
      qWarning() << "No record of Edge Id:" << y_edge_id;
      return;
    }

    QSharedPointer<RelayEdge> redge = _edges[y_edge_id];
    redge->SetRemoteEdgeId(x_edge_id);

    ProcessNewEdge(redge);
  }

  int RelayEdgeListener::GetEdgeId()
  {
    Dissent::Utils::Random &rand = Dissent::Utils::Random::GetInstance();
    int edge_id = rand.GetInt();
    while(_edges.contains(edge_id)) {
      edge_id = rand.GetInt();
    }
    return edge_id;
  }

  void RelayEdgeListener::IncomingData(const Request &notification)
  {
    QVariantHash msg = notification.GetData().toHash();

    bool ok;
    int x_edge_id = msg.value("x_edge_id").toInt(&ok);
    if(!ok) {
      qWarning() << "Received EdgeCreated but contains no from id.";
      return;
    }

    int y_edge_id = msg.value("y_edge_id").toInt(&ok);
    if(!ok) {
      qWarning() << "Received EdgeCreated but contains no to id.";
      return;
    }

    if(!_edges.contains(y_edge_id)) {
      qWarning() << "No record of Edge Id:" << y_edge_id;
      return;
    }

    QSharedPointer<RelayEdge> redge = _edges[y_edge_id];
    if(redge->GetRemoteEdgeId() != x_edge_id) {
      qWarning() << "Incorrect edge id.  Expected:" <<
        redge->GetRemoteEdgeId() << "found:" << x_edge_id;
      return;
    }
    redge->PushData(msg.value("data").toByteArray());
  }
}
}
