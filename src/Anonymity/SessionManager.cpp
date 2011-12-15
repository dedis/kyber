#include "../Messaging/RpcHandler.hpp"

#include "Session.hpp"
#include "SessionManager.hpp"

namespace Dissent {
namespace Anonymity {
  SessionManager::SessionManager(RpcHandler &rpc) :
    _register(this, &SessionManager::Register),
    _prepare(this, &SessionManager::Prepare),
    _begin(this, &SessionManager::Begin),
    _data(this, &SessionManager::IncomingData),
    _default_session(Id::Zero()),
    _default_set(false),
    _rpc(rpc)
  {
    _rpc.Register(&_register, "SM::Register");
    _rpc.Register(&_prepare, "SM::Prepare");
    _rpc.Register(&_begin, "SM::Begin");
    _rpc.Register(&_data, "SM::Data");
  }

  SessionManager::~SessionManager()
  {
    _rpc.Unregister("SM::Register");
    _rpc.Unregister("SM::Prepare");
    _rpc.Unregister("SM::Begin");
    _rpc.Unregister("SM::Data");
  }

  void SessionManager::AddSession(QSharedPointer<Session> session)
  {
    QObject::connect(session.data(), SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session[session->GetId()] = session;
    if(!_default_set) {
      _default_set = true;
      _default_session = session->GetId();
    }
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

  void SessionManager::Register(RpcRequest &request)
  {
    QSharedPointer<Session> session = GetSession(request);
    if(!session.isNull()) {
      session->ReceivedRegister(request);
    } else {
      QVariantMap response;
      response["result"] = false;
      response["online"] = false;
      request.Respond(response);
    }
  }

  void SessionManager::Prepare(RpcRequest &request)
  {
    QSharedPointer<Session> session = GetSession(request);
    if(!session.isNull()) {
      session->ReceivedPrepare(request);
    } else {
      QVariantMap response;
      response["result"] = false;
      response["online"] = false;
      request.Respond(response);
    }
  }

  void SessionManager::Begin(RpcRequest &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(!session.isNull()) {
      session->ReceivedBegin(notification);
    }
  }

  void SessionManager::IncomingData(RpcRequest &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(!session.isNull()) {
      session->IncomingData(notification);
    }
  }

  QSharedPointer<Session> SessionManager::GetSession(RpcRequest &msg)
  {
    QByteArray bid = msg.GetMessage()["session_id"].toByteArray();
    if(bid.isEmpty()) {
      qWarning() << "Received a wayward session message from " << msg.GetFrom()->ToString();
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

  void SessionManager::HandleSessionStop()
  {
    Session *session = qobject_cast<Session *>(sender());
    if(!session) {
      qCritical() << "Expected session found null";
      return;
    }

    QObject::disconnect(session, SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session.remove(session->GetId());
  }
}
}
