#include "SessionIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  SessionIdService::SessionIdService(SessionManager &sm) :
    SessionWebService(sm)
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
