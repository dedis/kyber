#include "Anonymity/Session.hpp"
#include "GetMessagesService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  const QString GetMessagesService::_offset_field = "offset";
  const QString GetMessagesService::_count_field = "count";
  const QString GetMessagesService::_wait_field = "wait";

  void GetMessagesService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QUrl url = wrp->GetRequest().GetUrl();

    int total = _message_list.count();
    int urlItemOffset = url.queryItemValue(_offset_field).toInt();
    bool wait_flag = QVariant(url.queryItemValue(_wait_field)).toBool();


    if((urlItemOffset == total) && wait_flag) {
      _pending_requests.append(wrp);
      return;
    }

    int offset = qMax(qMin(urlItemOffset, total), 0);
    int count = url.queryItemValue(_count_field).toInt();
    count = count < 0  || (total < offset + count) ? total : count + offset;

    QList<QVariant> messages;

    for(int idx = offset; idx < count; idx++) {
      messages.append(_message_list[idx]);
    }

    QVariantHash hash;
    hash["total"] = total;
    hash["offset"] = offset;
    hash["messages"] = messages;
    wrp->GetOutputData().setValue(hash);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
  }

  void GetMessagesService::HandleMessage(const QByteArray &data)
  {   
    _message_list.append(data);

    QList<QSharedPointer<WebRequest> > curr_pending_requests(_pending_requests);
    _pending_requests.clear();

    foreach(QSharedPointer<WebRequest> wrp, curr_pending_requests) {
      Handle(wrp);
    }
  }
}
}
}
