#include <QByteArray>

#include "Anonymity/Session.hpp"
#include "GetMessagesService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

  void GetMessagesService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QUrl url(wrp->GetRequest().GetUrl().toString());
    const QString query_offset = "offset";
    const QString query_count = "count";
    const QString query_wait = "wait";
    int total = _message_list.count();
    int urlItemOffset = (url.hasQueryItem(query_offset)) ? url.queryItemValue(query_offset).toInt() : 0;
    int offset = (url.hasQueryItem(query_offset)) ? qMax (qMin (urlItemOffset,total), 0) : 0;
    int count = (url.hasQueryItem(query_count)) ? url.queryItemValue(query_count).toInt() : -1;
    bool status = (url.hasQueryItem(query_wait))&&(!url.queryItemValue(query_wait).compare("true")||url.queryItemValue(query_wait).toInt()==1) ? true : false;
    int endpos = (offset + count -1 >= total || count < 0) ? total -1 : offset + count -1;
 
    QList<QVariant> qvlist;
    QVariantMap map;
    map["total"] = total;
    map["offset"] = offset;

    // if requested offset equals or is greater than total message length, 
    // than only return the next available message
    if(urlItemOffset == total && status && count!=0) {
       _pending_requests.append(wrp);
  return;
    }

    for(int i=offset; i<= endpos; i++) {
        QVariant v(_message_list.value(i));
        qvlist.append(v);
    }

    map["messages"] = qvlist;
    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
    //return;
  }

  void GetMessagesService::HandleMessage(const QByteArray &data)
  {   
      _message_list.append(data);

      if(!_pending_requests.count()) return;
      QList<QSharedPointer<WebRequest> > curr_pending_requests = QList<QSharedPointer<WebRequest> >(_pending_requests);
      _pending_requests.clear();
      foreach(QSharedPointer<WebRequest> wrp, curr_pending_requests) {
        Handle(wrp);
      }
  }
}
}
}

