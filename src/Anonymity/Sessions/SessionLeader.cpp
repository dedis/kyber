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

#include "SessionLeader.hpp"

namespace Dissent {
namespace Anonymity {
namespace Sessions {
  bool SessionLeader::EnableLogOffMonitor = true;

  SessionLeader::SessionLeader(const Group &group,
      const PrivateIdentity &ident, QSharedPointer<Network> network,
      const QSharedPointer<Session> &session) :
    _group(group),
    _ident(ident),
    _network(network),
    _session(session),
    _prepared(new ResponseHandler(this, "Prepared")),
    _round_idx(0)
  {
#ifdef NO_SESSION_MANAGER
    _network->Register("SM::Register", this, "HandleRegister");
    _network->Register("SM::Disconnect", this, "LinkDisconnect");
#endif
    foreach(const QSharedPointer<Connection> con,
        _network->GetConnectionManager()->GetConnectionTable().GetConnections())
    {
      QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
          this, SLOT(HandleDisconnectSlot()));
    }

    QObject::connect(_network->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        this, SLOT(HandleConnectionSlot(const QSharedPointer<Connection> &)));

    // We want to get this signal *after* we have received a Connection::Disconnect signal
    QObject::connect(_session.data(), SIGNAL(RoundFinished(const QSharedPointer<Round> &)),
        this, SLOT(HandleRoundFinished()), Qt::QueuedConnection);
  }

  SessionLeader::~SessionLeader()
  {
    // If SessionLeaderManager is being destructed causing this to be destructed and
    // this hasn't stopped, the Stopping signal will cause a nasty segfault
    // into a partially decomposed SessionLeaderManager
    QObject::disconnect(this, 0, 0, 0);
    Stop();
  }

  void SessionLeader::OnStart()
  {
    qDebug() << _ident.GetLocalId() << "SessionLeader started:" << GetSessionId();

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<SessionLeader, int>(this,
          &SessionLeader::CheckLogOffTimes, 0);

    _check_log_off_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb,
        LogOffCheckPeriod, LogOffCheckPeriod);
  }

  void SessionLeader::OnStop()
  {
    _check_log_off_event.Stop();
    _prepare_event.Stop();
    emit Stopping();
  }

  void SessionLeader::HandleRegister(const Request &request)
  {
    if(!Started()) {
      qDebug() << "Received a registration message when not started.";
      request.Failed(Response::InvalidInput, "SessionLeader not started");
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

    CheckRegistration();
  }

  bool SessionLeader::AllowRegistration(const QSharedPointer<ISender> &,
      const PublicIdentity &ident)
  {
    return !EnableLogOffMonitor || !_log_off_time.contains(ident.GetId());
  }

  void SessionLeader::CheckLogOffTimes(const int &)
  {
    qint64 cleared = Utils::Time::GetInstance().MSecsSinceEpoch() - LogOffPeriod;
    foreach(const Id &id, _log_off_time.keys()) {
      if(_log_off_time[id] < cleared) {
        _log_off_time.remove(id);
      }
    }
  }

  void SessionLeader::CheckRegistration()
  {
    if(GetGroup().Count() < Session::MinimumRoundSize) {
      return;
    }

    QDateTime start_time;

    if(!GetCurrentRound() || GetCurrentRound()->Stopped()) {
      start_time = _last_registration.addMSecs(InitialPeerJoinDelay);
    } else if(_prepare_event.Stopped()) {
      QDateTime to_use = GetCurrentRound()->GetCreateTime();
      if(GetCurrentRound()->Started()) {
        to_use = GetCurrentRound()->GetStartTime();
      }
      start_time = to_use.addMSecs(RoundRunningPeerJoinDelay);
    } else {
      return;
    }

    _prepare_event.Stop();
    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<SessionLeader, int>(this,
          &SessionLeader::CheckRegistrationCallback, 0);

    QDateTime ctime = Dissent::Utils::Time::GetInstance().CurrentTime();
    qint64 next = ctime.msecsTo(start_time);
    if(next < 0) {
      next = 0;
    }

    _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(
        cb, next);
  }

  void SessionLeader::CheckRegistrationCallback(const int &)
  {
    if(!GetCurrentRound() || !GetCurrentRound()->Started() || GetCurrentRound()->Stopped()) {
      SendPrepare();
    } else {
      qDebug() << "Letting the current round know that a peer joined event occurred.";
      GetCurrentRound()->PeerJoined();
    }
  }

  bool SessionLeader::SendPrepare()
  {
    if(!_session->CheckGroup(GetGroup())) {
      qDebug() << "All peers registered and ready but lack sufficient peers";
      return false;
    }

    Id round_id(Id::Zero().GetInteger() + _round_idx++);

    QVariantHash msg;
    msg["session_id"] = GetSessionId().GetByteArray();
    msg["round_id"] = round_id.GetByteArray();
    msg["interrupt"] = !GetCurrentRound() || GetCurrentRound()->Interrupted();

    Group group = GetGroup();
    QByteArray ser_group;
    QDataStream stream(&ser_group, QIODevice::WriteOnly);
    stream << group;
    msg["group"] = ser_group;

    qDebug() << "Sending prepare for round" << round_id;

    _prepared_peers.clear();
    _unprepared_peers = _registered_peers;
    foreach(const Id &id, _registered_peers) {
      _network->SendRequest(id, "SM::Prepare", msg, _prepared);
    }

    return true;
  }

  void SessionLeader::Prepared(const Response &response)
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

    Q_ASSERT(GetCurrentRound());
    Id round_id(response.GetData().toByteArray());
    if(GetCurrentRound()->GetRoundId() != round_id) {
      qDebug() << "Received a prepared message from the wrong round.  RoundId:" <<
        round_id << "from" << response.GetFrom()->ToString();
      return;
    }

    // Were we waiting on this one?
    if(_unprepared_peers.remove(sender->GetRemoteId()) > 0) {
      _prepared_peers.append(sender->GetRemoteId());
      CheckPrepares();
    }
  }

  void SessionLeader::CheckPrepares()
  {
    if(!GetCurrentRound() ||
        GetCurrentRound()->Stopped() ||
        GetCurrentRound()->Started())
    {
      return;
    }

    if(_unprepared_peers.size() > 0) {
      qDebug() << "Waiting on" << _unprepared_peers.size() <<
        "more prepared responses.";
      if(_unprepared_peers.size() < 5) {
        qDebug() << "Waiting on:" << _unprepared_peers.keys();
      }
      return;
    }

    QVariantHash msg;
    msg["session_id"] = GetSessionId().GetByteArray();
    msg["round_id"] = GetCurrentRound()->GetRoundId().GetByteArray();
    foreach(const Id &id, _prepared_peers) {
      _network->SendNotification(id, "SM::Begin", msg);
    }
  }

  void SessionLeader::HandleRoundFinished()
  {
    const QVector<int> bad = GetCurrentRound()->GetBadMembers();
    if(GetCurrentRound()->GetBadMembers().size()) {
      qWarning() << "Found some bad members...";
      Group group = GetGroup();
      foreach(int idx, GetCurrentRound()->GetBadMembers()) {
        RemoveMember(group.GetId(idx));
//        _bad_members.insert(GetGroup().GetId(idx));
      }
    }

    CheckRegistration();
  }

  void SessionLeader::LinkDisconnect(const Request &notification)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a LinkDisconnect from a non-IOverlaySender." <<
        sender->ToString();
      return;
    } else if(!GetGroup().Contains(sender->GetRemoteId())) {
      qWarning() << "Received a LinkDisconnect from a non-member." <<
        sender->GetRemoteId();
      return;
    }

    Id remote_id = Id(notification.GetData().toHash().value("remote_id").toByteArray());
    if(!GetGroup().Contains(remote_id)) {
      return;
    }

    switch(GetGroup().GetSubgroupPolicy()) {
      case Group::FixedSubgroup:
      case Group::ManagedSubgroup:
        // For now we leave this old logic in, this removes a sponsored link
        if(!GetGroup().GetSubgroup().Contains(remote_id)) {
          HandleDisconnect(remote_id);
        }
      default:
        break;
    }
    if(GetCurrentRound()) {
      GetCurrentRound()->HandleDisconnect(remote_id);
    }
  }

  void SessionLeader::HandleConnectionSlot(const QSharedPointer<Connection> &con)
  {
    // This could be optimized to only connect to members but too lazy...
    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));
  }

  void SessionLeader::HandleDisconnectSlot()
  {
    if(Stopped()) {
      return;
    }

    Connection *con = qobject_cast<Connection *>(sender());
    const Id &remote_id = con->GetRemoteId();
  
    if(!GetGroup().Contains(remote_id)) {
      return;
    }

    HandleDisconnect(remote_id);
  }

  void SessionLeader::HandleDisconnect(const Id &remote_id)
  {
    // This was a sponsored connection and we have no knowledge of it
    _log_off_time[remote_id] = Utils::Time::GetInstance().MSecsSinceEpoch();
    RemoveMember(remote_id);
    CheckPrepares();
  }

  void SessionLeader::AddMember(const PublicIdentity &gc)
  {
    if(!GetGroup().Contains(gc.GetId())) {
      _group = AddGroupMember(GetGroup(), gc, gc.GetSuperPeer());
    }

    _registered_peers.insert(gc.GetId(), gc.GetId());
  }

  void SessionLeader::RemoveMember(const Id &id)
  {
    _group = RemoveGroupMember(GetGroup(), id);
    _registered_peers.remove(id);
    _unprepared_peers.remove(id);
  }
}
}
}
