
#include "Anonymity/Session.hpp"
#include "SessionIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  
  SessionIdService::SessionIdService(QSharedPointer<Session> session) :
    SessionWebService(session) {}
  
  SessionIdService::~SessionIdService() {}

  void SessionIdService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QVariantMap map;

    if(_session.isNull()) {
      map["active"] = false;
      map["id"] = "";
    } else {
      map["active"] = true;
      map["id"] = _session->GetId().ToString();
    }

    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp);
    return;
  }

}
}
}

