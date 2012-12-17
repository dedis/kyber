#ifndef DISSENT_WEB_SESSION_SERVICE_GUARD
#define DISSENT_WEB_SESSION_SERVICE_GUARD

#include <QSharedPointer>

#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionManager.hpp"

#include "WebService.hpp"

namespace Dissent {
namespace Web {
  /**
   * A WebService that has access to the anonymity Session object
   */
  class SessionService : public WebService {
    public:
      typedef Anonymity::Sessions::Session Session;
      typedef Anonymity::Sessions::SessionManager SessionManager;

      explicit SessionService(SessionManager &sm);

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    protected:
      /**
       * Return the monitored session
       */
      QSharedPointer<Session> GetSession() { return m_sm.GetDefaultSession(); }
 
    private:
      SessionManager &m_sm;
  };
}
}

#endif
