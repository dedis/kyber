#ifndef DISSENT_WEB_SERVICES_SEND_MESSAGE_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_SEND_MESSAGE_SERVICE_GUARD

#include <QObject>

#include "Web/WebRequest.hpp"
#include "SessionWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /**
   * WebService for posting a message to the session.  The entire contents of
   * the HTTP POST body are interpreted to be the message to send.
   */
  class SendMessageService : public SessionWebService {
    public:
      SendMessageService(QSharedPointer<Session> session);
      SendMessageService(QSharedPointer<Node> node);
      
      virtual ~SendMessageService() {}

    private:
      /**
       * The main method for the web service.  If the status code wrp->status 
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);
  };
}
}
}

#endif
