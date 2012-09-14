#include "Utils/Serialization.hpp"
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
      QByteArray header(8, 0);
      Utils::Serialization::WriteInt(bytes.size(), header, 4);
      session->Send(header + bytes);
    }

    wrp->GetOutputData().setValue(hash);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
    return;
  }

}
}
}

