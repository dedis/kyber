#ifndef DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_MESSAGES_SERVICE_GUARD

#include <QByteArray> 
#include <QList>

#include "Web/WebRequest.hpp"
#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
   
  namespace {
    using namespace Dissent::Web;
  }

  /** 
   * Web service for getting the WebServer message
   * cache. The number of messages returned is
   * specified in WebServer
   */
  class GetMessagesService : public MessageWebService {
    Q_OBJECT

    public:
      
      GetMessagesService();
      
      virtual ~GetMessagesService();

      /**
       * The main method for the web service. 
       * If the status code wrp->status 
       * is not STATUS_OK, then the
       * output data might not be set.
       * @param request to be handled
       */
      void Handle(QSharedPointer<WebRequest> wrp);
    
    public slots:

      virtual void HandleIncomingMessage(const QByteArray &data);

    private:
      
      QList<QByteArray> _message_list;

  };

}
}
}

#endif
