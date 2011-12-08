
#include <QByteArray>

#include "Anonymity/Session.hpp"
#include "SendMessageService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  
  SendMessageService::SendMessageService(QSharedPointer<Session> session) :
    SessionWebService(session) {}

  SendMessageService::~SendMessageService() {}

  void SendMessageService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QVariantMap map;

    if(_session.isNull()) {
      map["session"] = false;
      map["id"] = "";
    } else {
      map["session"] = true;
      map["id"] = _session->GetId().ToString();

      QByteArray bytes = wrp->GetRequest().GetBody().toUtf8();
      _session->Send(bytes);
    }

    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp);
    return;
  }

}
}
}

