
#include "Anonymity/Session.hpp"
#include "GetNextMessageService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  void GetNextMessageService::Handle(QSharedPointer<WebRequest> wrp)
  {
    _pending_requests.append(wrp);
    qDebug() << "Queuing request for next message";
    return;
  }

  void GetNextMessageService::HandleMessage(const QByteArray &data)
  {
    qDebug() << "Got new message signal ... ";
    if(!_pending_requests.count()) return;

    QVariantMap map;
    map["message"] = data;

    qDebug() << "Responding to" << _pending_requests.count() << "requests!";
    foreach(QSharedPointer<WebRequest> wrp, _pending_requests) {
      wrp->GetOutputData().setValue(map);
      wrp->SetStatus(HttpResponse::STATUS_OK);

      emit FinishedWebRequest(wrp);
    }

    _pending_requests.clear();
  }
}
}
}
