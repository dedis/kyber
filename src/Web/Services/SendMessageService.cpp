#include "SendMessageService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  SendMessageService::SendMessageService(QSharedPointer<Session> session) :
    SessionWebService(session)
  {
  }

  SendMessageService::SendMessageService(QSharedPointer<Node> node) :
    SessionWebService(node)
  {
  }

  void SendMessageService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantMap map;

    if(session.isNull()) {
      map["active"] = false;
      map["id"] = "";
    } else {
      map["active"] = true;
      map["id"] = session->GetId().ToString();

      QByteArray bytes = wrp->GetRequest().GetBody().toUtf8();
      session->Send(bytes);
    }

    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp);
    return;
  }

}
}
}

