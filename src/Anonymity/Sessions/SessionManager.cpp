#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/RequestHandler.hpp"
#include "Messaging/RpcHandler.hpp"

#include "Session.hpp"
#include "SessionLeader.hpp"
#include "SessionManager.hpp"

namespace Dissent {

using Messaging::Response;
using Messaging::RequestHandler;

namespace Anonymity {
namespace Sessions {
  SessionManager::SessionManager(const QSharedPointer<RpcHandler> &rpc) :
    _default_session(Id::Zero()),
    _default_set(false),
    _rpc(rpc)
  {
    _rpc->Register("SM::Register", this, "HandleRegister");
    _rpc->Register("SM::Prepare", this, "HandlePrepare");
    _rpc->Register("SM::Prepared", this, "HandlePrepared");
    _rpc->Register("SM::Begin", this, "HandleBegin");
    _rpc->Register("SM::Data", this, "IncomingData");
    _rpc->Register("SM::Disconnect", this, "LinkDisconnect");
  }

  SessionManager::~SessionManager()
  {
    _rpc->Unregister("SM::Register");
    _rpc->Unregister("SM::Prepare");
    _rpc->Unregister("SM::Prepared");
    _rpc->Unregister("SM::Begin");
    _rpc->Unregister("SM::Data");
    _rpc->Unregister("SM::Disconnect");
  }

  void SessionManager::AddSession(const QSharedPointer<Session> &session)
  {
    QObject::connect(session.data(), SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session[session->GetSessionId()] = session;
    if(!_default_set) {
      _default_set = true;
      _default_session = session->GetSessionId();
    }
  }

  void SessionManager::AddSessionLeader(const QSharedPointer<SessionLeader> &sl)
  {
    QObject::connect(sl.data(), SIGNAL(Stopping()), this, SLOT(HandleSessionLeaderStop()));
    _id_to_session_leader[sl->GetSessionId()] = sl;
  }

  QSharedPointer<Session> SessionManager::GetSession(const Id &id)
  {
    return _id_to_session.value(id);
  }

  void SessionManager::SetDefaultSession(const Id &id)
  {
    if(_id_to_session.contains(id)) {
      _default_set = true;
      _default_session = id;
    }
  }

  QSharedPointer<Session> SessionManager::GetDefaultSession()
  {
    return _id_to_session.value(_default_session);
  }

  void SessionManager::LinkDisconnect(const Request &notification)
  {
    QSharedPointer<SessionLeader> sl = GetSessionLeader(notification);
    if(sl) {
      sl->LinkDisconnect(notification);
    }
  }

  void SessionManager::HandleRegister(const Request &request)
  {
    QSharedPointer<SessionLeader> sl = GetSessionLeader(request);
    if(sl) {
      sl->HandleRegister(request);
    } else {
      request.Failed(Response::InvalidInput, "No such session leader");
    }
  }

  void SessionManager::HandlePrepare(const Request &request)
  {
    QSharedPointer<Session> session = GetSession(request);
    if(session) {
      session->HandlePrepare(request);
    }
  }

  void SessionManager::HandlePrepared(const Request &notification)
  {
    QSharedPointer<SessionLeader> sl = GetSessionLeader(notification);
    if(sl) {
      sl->HandlePrepared(notification);
    }
  }

  void SessionManager::HandleBegin(const Request &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(session) {
      session->HandleBegin(notification);
    }
  }

  void SessionManager::IncomingData(const Request &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(session) {
      session->IncomingData(notification);
    }
  }

  QSharedPointer<Session> SessionManager::GetSession(const Request &msg)
  {
    QByteArray bid = msg.GetData().toHash().value("session_id").toByteArray();
    if(bid.isEmpty()) {
      qWarning() << "Received a wayward session (NULL) message from " <<
        msg.GetFrom()->ToString();
      return QSharedPointer<Session>();
    }

    Id id(bid);
    if(_id_to_session.contains(id)) {
      return _id_to_session[id];
    } else {
      qWarning() << "Received a wayward session message for session " <<
        id.ToString() << " from " << msg.GetFrom()->ToString();
      return QSharedPointer<Session>();
    }
  }

  QSharedPointer<SessionLeader> SessionManager::GetSessionLeader(const Request &msg)
  {
    QByteArray bid = msg.GetData().toHash().value("session_id").toByteArray();
    if(bid.isEmpty()) {
      qWarning() << "Received a wayward session leader (NULL) message from" <<
        msg.GetFrom()->ToString();
      return QSharedPointer<SessionLeader>();
    }

    Id id(bid);
    if(_id_to_session_leader.contains(id)) {
      return _id_to_session_leader[id];
    } else {
      qWarning() << "Received a wayward session leader (" << id <<
        ") from " << msg.GetFrom()->ToString();
      return QSharedPointer<SessionLeader>();
    }
  }

  void SessionManager::HandleSessionStop()
  {
    Session *session = qobject_cast<Session *>(sender());
    if(!session) {
      qCritical() << "Expected session found null";
      return;
    }

    QObject::disconnect(session, SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session.remove(session->GetSessionId());
  }

  void SessionManager::HandleSessionLeaderStop()
  {
    SessionLeader *sl = qobject_cast<SessionLeader *>(sender());
    if(!sl) {
      qCritical() << "Expected session found null";
      return;
    }

    QObject::disconnect(sl, SIGNAL(Stopping()), this, SLOT(HandleSessionLeaderStop()));
    _id_to_session_leader.remove(sl->GetSessionId());
  }

  void SessionManager::Stop()
  {
    foreach(const QSharedPointer<Session> &session, _id_to_session) {
      session->Stop();
    }

    foreach(const QSharedPointer<SessionLeader> &sl, _id_to_session_leader) {
      sl->Stop();
    }

    _id_to_session.clear();
    _id_to_session_leader.clear();
  }
}
}
}
