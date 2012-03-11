#include <algorithm>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Network.hpp"
#include "Crypto/Serialization.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  Session::Session(const QSharedPointer<GroupHolder> &group_holder,
      const PrivateIdentity &ident, const Id &session_id,
      QSharedPointer<Network> network, CreateRound create_round) :
    _group_holder(group_holder),
    _ident(ident),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _current_round(0),
    _prepared(new ResponseHandler(this, "Prepared")),
    _registered(new ResponseHandler(this, "Registered")),
    _get_data_cb(this, &Session::GetData),
    _round_idx(0),
    _prepare_waiting(false),
    _trim_send_queue(0),
    _registering(false)
  {
    QVariantHash headers = _network->GetHeaders();
    headers["session_id"] = _session_id.GetByteArray();
    _network->SetHeaders(headers);
    _network->SetMethod("SM::Data");

    if(IsLeader()) {
      AddMember(GetPublicIdentity(_ident));
    }

    foreach(const QSharedPointer<Connection> con,
        _network->GetConnectionManager()->GetConnectionTable().GetConnections())
    {
      QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
          this, SLOT(HandleDisconnect()));
    }

    QObject::connect(_network->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        this, SLOT(HandleConnection(const QSharedPointer<Connection> &)));
  }

  Session::~Session()
  {
    // If SessionManager is being destructed causing this to be destructed and
    // this hasn't stopped, the Stopping signal will cause a nasty segfault
    // into a partially decomposed SessionManager
    QObject::disconnect(this, 0, 0, 0);
    Stop();
  }

  void Session::OnStart()
  {
    qDebug() << _ident.GetLocalId() << "Session started:" << _session_id;

    if(!IsLeader() && ((_network->GetConnection(GetGroup().GetLeader()) != 0) ||
          ((GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup) &&
           (_network->GetConnectionManager()->GetConnectionTable().GetConnections().count() > 1))))
    {
      Register(0);
    }

    if(IsLeader()) {
      Dissent::Utils::TimerCallback *cb =
        new Dissent::Utils::TimerMethod<Session, int>(this,
            &Session::CheckLogOffTimes, 0);

      _check_log_off_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb,
          LogOffCheckPeriod, LogOffCheckPeriod);
    }
  }

  void Session::OnStop()
  {
    _check_log_off_event.Stop();
    _register_event.Stop();
    _prepare_event.Stop();

    QObject::disconnect(this, SLOT(HandleDisconnect()));

    if(!_current_round.isNull()) {
      QObject::disconnect(_current_round.data(), SIGNAL(Finished()), this,
          SLOT(HandleRoundFinished()));
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
  }

  bool Session::CheckGroup()
  {
    Dissent::Connections::ConnectionTable &ct =
      _network->GetConnectionManager()->GetConnectionTable();

    if(GetGroup().Count() < MinimumRoundSize) {
      qDebug() << "Not enough peers in group to support an anonymous session,"
        "need" << (GetGroup().Count() - MinimumRoundSize) << "more";
      return false;
    }

    const Group &group = GetGroup();
    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      if(group.GetSubgroup().Contains(_ident.GetLocalId())) {
        foreach(const PublicIdentity &gc, group.GetSubgroup()) {
          if(ct.GetConnection(gc.GetId()) == 0) {
            qDebug() << "Missing a subgroup connection.";
            return false;
          }
        }
      } else {
        bool found = false;
        foreach(const QSharedPointer<Connection> &con, ct.GetConnections()) {
          if(group.GetSubgroup().Contains(con->GetRemoteId())) {
            found = true;
            break;
          }
        }
        if(!found) {
          qDebug() << "Missing a subgroup connection.";
          return false;
        }
      }
      return true;
    } else {
      bool good = true;
      foreach(const PublicIdentity &gc, group) {
        if(!ct.GetConnection(gc.GetId())) {
          qDebug() << "Missing a connection" << gc.GetId();
          good = false;
        }
      }

      return good;
    }
  }

  void Session::Register(const int &)
  {
    _registering = true;
    QVariantHash container;
    container["session_id"] = _session_id.GetByteArray();

    QByteArray ident;
    QDataStream stream(&ident, QIODevice::WriteOnly);
    stream << GetPublicIdentity(_ident);
    container["ident"] = ident;

    _network->SendRequest(GetGroup().GetLeader(), "SM::Register", container, _registered);
  }

  void Session::ReceivedRegister(const Request &request)
  {
    if(!IsLeader()) {
      qWarning() << "Received a registration message when not a leader.";
      request.Failed(Response::WrongDestination, "Not the leader");
      return;
    } else if(!Started()) {
      qDebug() << "Received a registration message when not started.";
      request.Failed(Response::InvalidInput, "Session not started");
      return;
    }

    QDataStream stream(request.GetData().toHash().value("ident").toByteArray());
    PublicIdentity ident;
    stream >> ident;

    if(!ident.GetVerificationKey()->IsValid()) {
      qWarning() << "Received a registration request with invalid credentials";
      request.Failed(Response::InvalidInput, "PrivateIdentity do not match Id");
      return;
    }

    if(!AllowRegistration(request.GetFrom(), ident)) {
      qDebug() << "Peer," << ident << ", has connectivity problems," <<
       "deferring registration until later.";
      request.Failed(Response::Other,
          "Unable to register at this time, try again later.");
      return;
    }

    qDebug() << "Received a valid registration message from:" << ident;
    _last_registration = Dissent::Utils::Time::GetInstance().CurrentTime();

    AddMember(ident);
    request.Respond(true);

    if(!_prepare_event.Stopped()) {
      return;
    }

    qDebug() << "Starting a new prepare event due to peer join.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this,
          &Session::CheckRegistration, 0);

    _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb,
        static_cast<int>(PeerJoinDelay * 1.1), PeerJoinDelay);
  }

  bool Session::AllowRegistration(const QSharedPointer<ISender> &,
      const PublicIdentity &ident)
  {
    return !_log_off_time.contains(ident.GetId());
  }

  void Session::CheckLogOffTimes(const int &)
  {
    qint64 cleared = Utils::Time::GetInstance().MSecsSinceEpoch() - LogOffPeriod;
    foreach(const Id &id, _log_off_time.keys()) {
      if(_log_off_time[id] < cleared) {
        _log_off_time.remove(id);
      }
    }
  }

  void Session::CheckRegistration(const int &)
  {
    QDateTime ctime = Dissent::Utils::Time::GetInstance().CurrentTime();
    QDateTime min_delay = _last_registration.addMSecs(PeerJoinDelay);
    if(ctime <= min_delay) {
      qDebug() << "Not enough time has passed between peer joins to" <<
        "start a session:" << _last_registration << "-" << ctime <<
        "=" << min_delay.secsTo(ctime);
      return;
    }

    qDebug() << "Enough time has passed between peer joins to start a round.";
    _prepare_event.Stop();

    if(_current_round.isNull() || !_current_round->Started() ||
          _current_round->Stopped())
    {
      SendPrepare();
    } else if(IsLeader()) {
      qDebug() << "Letting the current round know that a peer joined event occurred.";
      _current_round->PeerJoined();
    }
  }

  void Session::Registered(const Response &response)
  {
    if(Stopped()) {
      return;
    }

    if(response.Successful() && response.GetData().toBool()) {
      qDebug() << _ident.GetLocalId() << "registered and waiting to go.";
      return;
    }

    qDebug() << "Unable to register due to" << response.GetError() <<
      "Trying again later.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this, &Session::Register, 0);
    _register_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, 5000);
  }

  bool Session::SendPrepare()
  {
    if(!CheckGroup()) {
      qDebug() << "All peers registered and ready but lack sufficient peers";
      _prepare_waiting = true;
      return false;
    }

    Id round_id(Id::Zero().GetInteger() + _round_idx++);

    QVariantHash msg;
    msg["session_id"] = _session_id.GetByteArray();
    msg["round_id"] = round_id.GetByteArray();
    msg["interrupt"] = _current_round.isNull() ?
      true : _current_round->Interrupted();

    if(GetGroup() != _shared_group) {
      _shared_group = GetGroup();
      QByteArray group;
      QDataStream stream(&group, QIODevice::WriteOnly);
      stream << _shared_group;
      msg["group"] = group;
    }

    qDebug() << "Sending prepare for round" << round_id <<
      "new group:" << msg.contains("group");

    _prepared_peers.clear();
    foreach(const Id &id, _registered_peers) {
      _network->SendRequest(id, "SM::Prepare", msg, _prepared);
    }

    NextRound(round_id);
    return true;
  }

  void Session::ReceivedPrepare(const Request &request)
  {
    if(_prepare_waiting) {
      _prepare_waiting = false;
    }

    QVariantHash msg = request.GetData().toHash();

    if(!_current_round.isNull() && !_current_round->Stopped() &&
        _current_round->Started())
    {
      _prepare_waiting = true;
      _prepare_request = request;
      if(msg.value("interrupt").toBool()) {
        _current_round->Stop("Round interrupted.");
      }
      return;
    }

    QByteArray brid = msg.value("round_id").toByteArray();
    if(brid.isEmpty()) {
      qDebug() << "ReceivedPrepare: Invalid round id";
      return;
    }

    Id round_id(brid);

    if(msg.contains("group")) {
      qDebug() << "Prepare contains new group";
      QDataStream stream(msg.value("group").toByteArray());
      Group group;
      stream >> group;
      _group_holder->UpdateGroup(group);
    }

    if(!CheckGroup()) {
      qDebug() << "Received a prepare message but lack of sufficient peers";
      _prepare_waiting = true;
      _prepare_request = request;
      return;
    }

    NextRound(round_id);
    request.Respond(brid);
    _prepare_request = Request();
  }

  void Session::Prepared(const Response &response)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      response.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a prepared message from a non-IOverlaySender:" <<
        response.GetFrom()->ToString();
      return;
    } else if(!GetGroup().Contains(sender->GetRemoteId())) {
      qWarning() << "Received a prepared message from a non-group member:" <<
        response.GetFrom()->ToString();
      return;
    }

    Id round_id(response.GetData().toByteArray());

    if(_current_round->GetRoundId() != round_id) {
      qDebug() << "Received a prepared message from the wrong round.  RoundId:" <<
        round_id << "from" << response.GetFrom()->ToString();
      return;
    }

    _prepared_peers.insert(sender->GetRemoteId(), sender->GetRemoteId());
    if(_prepared_peers.size() != _registered_peers.size()) {
      qDebug() << "Waiting on" << (_registered_peers.size() - _prepared_peers.size()) <<
        "more prepared responses.";
      return;
    }

    QVariantHash msg;
    msg["session_id"] = _session_id.GetByteArray();
    msg["round_id"] = round_id.GetByteArray();
    foreach(const Id &id, _prepared_peers) {
      _network->SendNotification(id, "SM::Begin", msg);
    }

    _prepared_peers.clear();
  }

  void Session::ReceivedBegin(const Request &notification)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a begin from a non-IOverlaySender." <<
        notification.GetFrom()->ToString();
      return;
    }

    if(GetGroup().GetLeader() != sender->GetRemoteId()) {
      qWarning() << "Received a begin from someone other than the leader:" <<
        notification.GetFrom()->ToString();
      return;
    }

    if(_current_round.isNull()) {
      qWarning() << "Received a begin without having a valid round...";
      return;
    }

    Id round_id(notification.GetData().toHash().value("round_id").toByteArray());
    if(_current_round->GetRoundId() != round_id) {
      qWarning() << "Received a begin for a different round, expected:" <<
        _current_round->GetRoundId() << "got:" << round_id;
      return;
    }

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString() << "started" << _current_round->Started();
    emit RoundStarting(_current_round);
    _current_round->Start();
  }

  void Session::HandleRoundFinished()
  {
    Round *round = qobject_cast<Round *>(sender());
    if(round != _current_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    qDebug() << "Session" << ToString() << "round" <<
      _current_round->ToString() << "finished due to" <<
      _current_round->GetStoppedReason();

    if(!round->Successful()) {
      _trim_send_queue = 0;
    }

    emit RoundFinished(_current_round);

    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    const QVector<int> bad = round->GetBadMembers();
    if(round->GetBadMembers().size() != 0) {
      qWarning() << "Found some bad members...";
      if(IsLeader()) {
        Group group = GetGroup();
        foreach(int idx, round->GetBadMembers()) {
          RemoveMember(group.GetId(idx));
          _bad_members.insert(GetGroup().GetId(idx));
        }
      }
    }

    if(IsLeader() && _prepare_event.Stopped()) {
      Dissent::Utils::TimerCallback *cb =
        new Dissent::Utils::TimerMethod<Session, int>(
            this, &Session::CheckRegistration, 0);
      _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, 0, 5000);
    } else if(_prepare_waiting) {
      ReceivedPrepare(_prepare_request);
    }
  }

  void Session::NextRound(const Id &round_id)
  {
    _current_round = _create_round(GetGroup(), _ident, round_id,
        _network, _get_data_cb);

    qDebug() << "Session" << ToString() << "preparing new round" <<
      _current_round->ToString();

    _current_round->SetSink(this);
    QObject::connect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinished()));
  }

  void Session::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Session is stopped.";
      return;
    }

    _send_queue.append(data);
  }

  void Session::IncomingData(const Request &notification)
  {
    if(!_current_round.isNull()) {
      _current_round->IncomingData(notification);
    } else {
      qWarning() << "Received a data message without having a valid round.";
    }
  }

  void Session::HandleConnection(const QSharedPointer<Connection> &con)
  {
    if(!_registering && ((GetGroup().GetLeader() == con->GetRemoteId()) ||
        (GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup)))
    {
      Register(0);
    }

    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnect()));

    if(_prepare_waiting && CheckGroup()) {
      ReceivedPrepare(_prepare_request);
    }
  }

  void Session::HandleDisconnect()
  {
    if(Stopped()) {
      return;
    }

    Connection *con = qobject_cast<Connection *>(sender());
    const Id &remote_id = con->GetRemoteId();

    if(IsLeader()) {
      _log_off_time[remote_id] = Utils::Time::GetInstance().MSecsSinceEpoch();
    }

    if(!GetGroup().Contains(remote_id)) {
      return;
    }

    if((GetGroup().GetLeader() == remote_id) ||
        (_network->GetConnectionManager()->GetConnectionTable().GetConnections().count() == 1))
    {
      _registering = false;
    }

    if(IsLeader()) {
      RemoveMember(remote_id);
    } else if((GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup) &&
        (GetGroup().GetSubgroup().Contains(_ident.GetLocalId())))
    {
      // Ideally the above would only include disconnects between a client
      // and a server unfortunately due to the behavior of the current rounds,
      // if two servers disconnect they livelock...
      QVariantHash container;
      container["session_id"] = _session_id.GetByteArray();
      container["remote_id"] = remote_id.GetByteArray();
      _network->SendNotification(GetGroup().GetLeader(), "SM::Disconnect", container);
    } else {
      // The same situation as above, if there exists a disconnect, notify the
      // leader to restart the session...
      QVariantHash container;
      container["session_id"] = _session_id.GetByteArray();
      container["remote_id"] = remote_id.GetByteArray();
      _network->SendNotification(GetGroup().GetLeader(), "SM::Disconnect", container);
    }

    if(!_current_round.isNull()) {
      _current_round->HandleDisconnect(remote_id);
    }

    if(GetGroup().GetLeader() == con->GetRemoteId()) {
      qWarning() << "Leader disconnected!";
    }
  }

  void Session::LinkDisconnect(const Request &notification)
  {
    Id remote_id = Id(notification.GetData().toHash().value("remote_id").toByteArray());
    if(!GetGroup().Contains(remote_id) || _current_round.isNull()) {
      return;
    }

    // Ideally we should just push a handle disconnect into the round and
    // then let a timeout occur on the prepare message...
    if(GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup) {
      // In both cases, the system cannot distinguish (or more accurately handle)
      // transient problems, so unfortunately a disconnected client does not
      // differ from one on a poor network link
      if(!GetGroup().GetSubgroup().Contains(remote_id)) {
        RemoveMember(remote_id);
      }
      _current_round->HandleDisconnect(remote_id);
    } else {
      // We'll either get a disconnect or it was transient and the round needs
      // to restart ... the process is the same either way
      _current_round->HandleDisconnect(remote_id);
    }
  }

  void Session::AddMember(const PublicIdentity &gc)
  {
    if(!GetGroup().Contains(gc.GetId())) {
      bool subgroup = (GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup)
        && gc.GetSuperPeer();
      _group_holder->UpdateGroup(AddGroupMember(GetGroup(), gc, subgroup));
    }

    _registered_peers.insert(gc.GetId(), gc.GetId());
  }

  void Session::RemoveMember(const Id &id)
  {
    _group_holder->UpdateGroup(RemoveGroupMember(GetGroup(), id));
    _registered_peers.remove(id);
    _prepared_peers.remove(id);
  }

  QPair<QByteArray, bool> Session::GetData(int max)
  {
    if(_trim_send_queue > 0) {
      _send_queue = _send_queue.mid(_trim_send_queue);
    }

    QByteArray data;
    int idx = 0;
    while(idx < _send_queue.count()) {
      if(max < _send_queue[idx].count()) {
        qDebug() << "Messaging in queue is bigger than max data:" <<
          _send_queue[idx].count() << "/" << max;
        idx++;
        continue;
      } else if(max < (data.count() + _send_queue[idx].count())) {
        break;
      }

      data.append(_send_queue[idx++]);
    }

    _trim_send_queue = idx;

    bool more = _send_queue.count() < _trim_send_queue;
    return QPair<QByteArray, bool>(data, more);
  }
}
}
