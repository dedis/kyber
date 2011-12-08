
#include "Anonymity/Session.hpp"
#include "SessionIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  SessionIdService::SessionIdService(QSharedPointer<Session> session) :
    SessionWebService(session)
  {
  }
  
  SessionIdService::SessionIdService(QSharedPointer<Node> node) :
    SessionWebService(node)
  {
  }

  void SessionIdService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantMap map;

    if(session.isNull()) {
      map["active"] = false;
      map["id"] = "";
    } else {
      map["active"] = true;
      map["id"] = session->GetId().ToString();
    }

    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp);
    return;
  }
}
}
}
