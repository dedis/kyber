#ifndef DISSENT_WEB_SEND_MESSAGE_SERVICE_GUARD
#define DISSENT_WEB_SEND_MESSAGE_SERVICE_GUARD

#include <QObject>

#include "SessionService.hpp"

namespace Dissent {
namespace Web {
  /**
   * WebService for posting a message to the session.  The entire contents of
   * the HTTP POST body are interpreted to be the message to send.
   */
  class SendMessageService : public SessionService {
    public:
      explicit SendMessageService(SessionManager &sm);
      
      virtual ~SendMessageService();

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);
  };
}
}

#endif
