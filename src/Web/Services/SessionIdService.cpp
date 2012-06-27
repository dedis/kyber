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
    QVariantHash hash;

    if(session.isNull()) {
      hash["active"] = false;
      hash["id"] = "";
    } else {
      hash["active"] = true;
      hash["id"] = session->GetSessionId().ToString();
    }

    wrp->GetOutputData().setValue(hash);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
    return;
  }
}
}
}
