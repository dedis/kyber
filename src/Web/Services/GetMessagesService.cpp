
#include <QByteArray>

#include "Anonymity/Session.hpp"
#include "GetMessagesService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  void GetMessagesService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QList<QVariant> qvlist;
    for(int i=_message_list.count()-1; i>=0; --i) {
      QVariant v(_message_list.value(i));
      qvlist.append(v);
    }

    wrp->GetOutputData().setValue(qvlist);
    wrp->SetStatus(HttpResponse::STATUS_OK);

    emit FinishedWebRequest(wrp);
    return;
  }

  void GetMessagesService::HandleMessage(const QByteArray &data)
  {
    _message_list.append(data);
  }
}
}
}

