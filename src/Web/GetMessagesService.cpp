#include "Utils/Serialization.hpp"
#include "GetMessagesService.hpp"

#include <QDebug>

namespace Dissent {
namespace Web {
  const QString GetMessagesService::OFFSET_FIELD = "offset";
  const QString GetMessagesService::COUNT_FIELD = "count";
  const QString GetMessagesService::WAIT_FIELD = "wait";

  void GetMessagesService::HandleRequest(QHttpRequest *request,
      QHttpResponse *response)
  {
    QUrl url = request->url();

    int total = m_message_list.count();
    int urlItemOffset = url.queryItemValue(OFFSET_FIELD).toInt();
    bool wait_flag = QVariant(url.queryItemValue(WAIT_FIELD)).toBool();

    if((urlItemOffset == total) && wait_flag) {
      m_pending.append(ReqRep(request, response));
      return;
    }

    int offset = qMax(qMin(urlItemOffset, total), 0);
    int count = url.queryItemValue(COUNT_FIELD).toInt();
    count = count < 0  || (total < offset + count) ? total : count + offset;

    QList<QVariant> messages;

    for(int idx = offset; idx < count; idx++) {
      messages.append(m_message_list[idx]);
    }

    QVariantHash data;
    data["total"] = total;
    data["offset"] = offset;
    data["messages"] = messages;

    SendJsonResponse(response, data);
  }

  void GetMessagesService::HandleMessage(const QByteArray &data)
  {
    int offset = 0;
    while(offset + 8 < data.size()) {
      int length = Utils::Serialization::ReadInt(data, offset);
      if(length < 0 || data.size() < offset + 8 + length) {
        return;
      }

      int zeroes = Utils::Serialization::ReadInt(data, offset + 4);
      if(zeroes == 0) {
        QByteArray message = data.mid(offset + 8, length);
        m_message_list.append(message);
      }

      offset += 8 + length;
    }

    QList<ReqRep> curr_pending(m_pending);
    m_pending.clear();

    foreach(ReqRep reqrep, curr_pending) {
      HandleRequest(reqrep.first, reqrep.second);
    }
  }
}
}
