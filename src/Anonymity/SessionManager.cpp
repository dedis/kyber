#include "SessionManager.hpp"

namespace Dissent {
namespace Anonymity {
  SessionManager::SessionManager(RpcHandler *rpc) :
    _ready(*this, &SessionManager::Ready),
    _data(*this, &SessionManager::IncomingData),
    _rpc(rpc)
  {
    _rpc->Register(&_data, "SM::Data");
    _rpc->Register(&_ready, "SM::Ready");
  }

  SessionManager::~SessionManager()
  {
    _rpc->Unregister("SM::Data");
    _rpc->Unregister("SM::Ready");
  }

  void SessionManager::AddSession(Session *session)
  {
    QObject::connect(session, SIGNAL(Closed(Session *)),
          this, SLOT(HandleSessionClose(Session *)));
    _id_to_session[session->GetId()] = session;
    if(session->IsLeader()) {
      // dequeue any notifications
    }
  }

  void SessionManager::Ready(RpcRequest &request)
  {
    Session *session = GetSession(request);
    if(session) {
      session->ReceivedReady(request);
    } else {
      // queue it...
    }
  }

  void SessionManager::IncomingData(RpcRequest &notification)
  {
    Session *session = GetSession(notification);
    if(session) {
      session->IncomingData(notification);
    }
  }

  Session *SessionManager::GetSession(RpcRequest &msg)
  {
    QByteArray bid = msg.GetMessage()["session_id"].toByteArray();
    if(bid.isEmpty()) {
      qWarning() << "Received a wayward session message from " << msg.GetFrom()->ToString();
      return 0;
    }

    Id id(bid);
    if(_id_to_session.contains(id)) {
      return _id_to_session[id];
    } else {
      qWarning() << "Received a wayward session message for session " <<
        id.ToString() << " from " << msg.GetFrom()->ToString();
      return 0;
    }
  }

  void SessionManager::HandleSessionClose(Session *session)
  {
    QObject::disconnect(session, SIGNAL(Closed(Session *)),
          this, SLOT(HandleSessionClose(Session *)));
    _id_to_session.remove(session->GetId());
  }
}
}
