#include "SendMessageService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  SendMessageService::SendMessageService(SessionManager &sm) :
    SessionWebService(sm)
  {
  }

  void SendMessageService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantHash hash;

    if(session.isNull()) {
      hash["active"] = false;
      hash["id"] = "";
    } else {
      hash["active"] = true;
      hash["id"] = session->GetSessionId().ToString();

      QByteArray bytes = wrp->GetRequest().GetBody().toUtf8();
      session->Send(bytes);
    }

    wrp->GetOutputData().setValue(hash);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
    return;
  }

}
}
}

