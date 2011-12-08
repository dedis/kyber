
#include "Anonymity/Session.hpp"
#include "GetNextMessageService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  
  GetNextMessageService::GetNextMessageService() :
    MessageWebService() {};

  GetNextMessageService::~GetNextMessageService() {}

  void GetNextMessageService::Handle(QSharedPointer<WebRequest> wrp)
  {
    _pending_requests.insert(wrp);
    qDebug() << "Queuing request for next message";
    return;
  }

  void GetNextMessageService::HandleIncomingMessage(const QByteArray &data)
  {
    qDebug() << "Got new message signal ... ";
    if(!_pending_requests.count()) return;

    QVariantMap map;
    map["message"] = data;

    qDebug() << "Responding to" << _pending_requests.count() << "requests!";
    QSet<QSharedPointer<WebRequest> >::iterator i;
    for(i=_pending_requests.begin(); i!=_pending_requests.end(); ++i) {
      QSharedPointer<WebRequest> wrp = *i;
      wrp->GetOutputData().setValue(map);
      wrp->SetStatus(HttpResponse::STATUS_OK);

      emit FinishedWebRequest(wrp);
    }

    _pending_requests.clear();
  }
  
}
}
}

