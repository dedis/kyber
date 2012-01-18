#ifndef DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD

#include <QByteArray> 
#include <QList>

#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
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

    private:
      /**
       * The main method for the web service.  If the status code wrp->status
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);

      virtual void HandleMessage(const QByteArray &data);

      QList<QSharedPointer<WebRequest> > _pending_requests;

      QList<QByteArray> _message_list;
      
      QHash<QString, QVariant> _data; 
      
  };

}
}
}

#endif
