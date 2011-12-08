#ifndef DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD

#include <QByteArray> 
#include <QList>

#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /** 
   * Web service for getting the WebServer message
   * cache. The number of messages returned is
   * specified in WebServer
   */
  class GetMessagesService : public MessageWebService {
    public:
      virtual ~GetMessagesService() {}

    private:
      /**
       * The main method for the web service.  If the status code wrp->status
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);

      virtual void HandleMessage(const QByteArray &data);

      QList<QByteArray> _message_list;
  };

}
}
}

#endif
