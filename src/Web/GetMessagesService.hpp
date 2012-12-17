#ifndef DISSENT_WEB_GET_MESSAGES_SERVICE_GUARD
#define DISSENT_WEB_GET_MESSAGES_SERVICE_GUARD

#include <QByteArray> 
#include <QList>

#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
  /** 
   * Web service for getting the WebServer target messages from 
   * message cache. Get total k number of messages from the beginning of i'th entered message to the (i+k-1)th message.
   */
  class GetMessagesService : public MessageWebService {
    public:
      explicit GetMessagesService()
      {
      }

      virtual ~GetMessagesService() {}

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    private:
      virtual void HandleMessage(const QByteArray &data);

      typedef QPair<QHttpRequest *, QHttpResponse *> ReqRep;
      QList<ReqRep> m_pending;

      QList<QByteArray> m_message_list;

      static const QString OFFSET_FIELD;
      static const QString COUNT_FIELD;
      static const QString WAIT_FIELD;
  };

}
}

#endif
